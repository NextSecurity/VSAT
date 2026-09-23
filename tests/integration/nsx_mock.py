"""Mock NSX Manager (Policy/Manager API subset) for VSAT integration tests.

Serves HTTPS on 127.0.0.1:<port> with a self-signed certificate (cert.pem/key.pem in the
working directory). Implements session login with XSRF token + JSESSIONID, cursor
pagination, and deliberate traps: a credential-stealing redirect, a 403 and a 404.
Every non-session mutation attempt is logged as MUTATION-ATTEMPT (the test asserts none).
Synthetic data only.
"""
import http.server, ssl, json, urllib.parse, sys, secrets
TOKEN = secrets.token_hex(16); SESS = secrets.token_hex(16)
LOG = open('requests.log', 'w')
G = '/infra/domains/default/groups/'
def page(items, q, size=2):
    c = int(q.get('cursor', ['0'])[0]); nxt = c + size
    r = {'results': items[c:nxt], 'result_count': len(items)}
    if nxt < len(items): r['cursor'] = str(nxt)
    return r
VMS = [{'external_id': '5000aaaa-0000-0000-0000-00000000000%d' % i, 'display_name': 'vm%d' % i} for i in range(5)]
DATA = {
 '/api/v1/node/version': {'product_version': '4.2.1.3', 'node_version': '4.2.1.3.0.24533884'},
 '/api/v1/cluster/status': {'mgmt_cluster_status': {'status': 'STABLE'}},
 '/api/v1/cluster/backups/config': {'backup_enabled': True, 'backup_schedule': {'resource_type': 'IntervalBackupSchedule'}, 'remote_file_server': {'server': '192.0.2.50'}},
 '/api/v1/node/services/syslog/exporters': {'results': []},
 '/api/v1/node/aaa/auth-policy': {'api_max_auth_failures': 5, 'api_failed_auth_lockout_period': 900, 'minimum_password_length': 15},
 '/policy/api/v1/infra/settings/firewall/security': {'enable_firewall': True},
 '/policy/api/v1/infra/settings/firewall/security/exclude-list': {'members': []},
}
LISTS = {
 '/api/v1/trust-management/certificates': [],
 '/api/v1/fabric/compute-managers': [{'id': 'cm1', 'display_name': 'vc', 'server': 'vc-other.example.local'}],
 '/api/v1/transport-nodes/state': [{'transport_node_id': 'tn1', 'state': 'success'}],
 '/api/v1/transport-nodes': [{'node_id': 'tn1', 'display_name': 'esx-a', 'node_deployment_info': {'resource_type': 'HostNode'}}],
 '/api/v1/edge-clusters': [{'id': 'ec1', 'display_name': 'ec', 'members': [{'transport_node_id': 'tn1'}]}],
 '/policy/api/v1/infra/tier-0s': [{'path': '/infra/tier-0s/t0', 'display_name': 't0', 'ha_mode': 'ACTIVE_STANDBY'}],
 '/policy/api/v1/infra/tier-0s/t0/locale-services': [{'id': 'default', 'edge_cluster_path': '/infra/sites/default/enforcement-points/default/edge-clusters/ec1'}],
 '/policy/api/v1/infra/tier-1s': [{'path': '/infra/tier-1s/t1', 'display_name': 't1', 'tier0_path': '/infra/tier-0s/t0'}],
 '/policy/api/v1/infra/tier-1s/t1/locale-services': [],
 '/policy/api/v1/infra/tier-1s/t1/nat/USER/nat-rules': [{'id': 'n1', 'action': 'DNAT', 'enabled': True, 'firewall_match': 'BYPASS'}],
 '/policy/api/v1/infra/segments': [{'path': '/infra/segments/web', 'display_name': '<script>alert(1)</script>', 'unique_id': 'u1', 'connectivity_path': '/infra/tier-1s/t1'}],
 '/policy/api/v1/infra/domains/default/groups': [{'path': G + 'g%d' % i, 'display_name': 'g%d' % i} for i in range(3)],
 '/policy/api/v1/infra/domains/default/security-policies': [{'path': '/infra/domains/default/security-policies/app', 'display_name': 'app', 'category': 'Application', 'sequence_number': 10},
     {'path': '/infra/domains/default/security-policies/default-layer3-section', 'display_name': 'Default Layer3 Section', 'category': 'Application', 'sequence_number': 999999, 'is_default': True}],
 '/policy/api/v1/infra/domains/default/security-policies/app/rules': [
     {'path': '/infra/domains/default/security-policies/app/rules/r1', 'id': 'r1', 'display_name': 'any-any', 'sequence_number': 1, 'source_groups': ['ANY'], 'destination_groups': ['ANY'], 'services': ['ANY'], 'scope': ['ANY'], 'action': 'ALLOW'},
     {'path': '/infra/domains/default/security-policies/app/rules/r2', 'id': 'r2', 'display_name': 'to-empty', 'sequence_number': 2, 'source_groups': [G + 'g0'], 'destination_groups': [G + 'g2'], 'services': ['ANY'], 'scope': ['ANY'], 'action': 'DROP'}],
 '/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules': [
     {'path': '/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule', 'id': 'default-layer3-rule', 'display_name': 'Default Rule', 'sequence_number': 1, 'source_groups': ['ANY'], 'destination_groups': ['ANY'], 'services': ['ANY'], 'scope': ['ANY'], 'action': 'DROP', 'logged': True}],
 '/policy/api/v1/infra/domains/default/gateway-policies': [],
 '/api/v1/fabric/virtual-machines': [{'external_id': v['external_id'], 'display_name': v['display_name']} for v in VMS],
 G.replace('/infra', '/policy/api/v1/infra') + 'g0/members/virtual-machines': VMS[:3],
 G.replace('/infra', '/policy/api/v1/infra') + 'g0/members/ip-addresses': ['10.0.0.1'],
 G.replace('/infra', '/policy/api/v1/infra') + 'g1/members/virtual-machines': VMS[3:],
 G.replace('/infra', '/policy/api/v1/infra') + 'g1/members/ip-addresses': [],
 G.replace('/infra', '/policy/api/v1/infra') + 'g2/members/virtual-machines': [],
 G.replace('/infra', '/policy/api/v1/infra') + 'g2/members/ip-addresses': [],
}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj=None, headers=None):
        b = json.dumps(obj).encode() if obj is not None else b''
        self.send_response(code)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def authed(self):
        return self.headers.get('X-XSRF-TOKEN') == TOKEN and ('JSESSIONID=' + SESS) in (self.headers.get('Cookie') or '')
    def do_POST(self):
        u = urllib.parse.urlparse(self.path); LOG.write('POST %s\n' % u.path); LOG.flush()
        n = int(self.headers.get('Content-Length') or 0); body = self.rfile.read(n).decode()
        if u.path == '/api/session/create':
            f = urllib.parse.parse_qs(body)
            if f.get('j_username') == ['auditor'] and f.get('j_password') == ['S3cret!pw']:
                return self.send(200, {}, {'X-XSRF-TOKEN': TOKEN, 'Set-Cookie': 'JSESSIONID=%s; Path=/; Secure; HttpOnly' % SESS})
            return self.send(403, {'error_message': 'Not authenticated'})
        if u.path == '/api/session/destroy': return self.send(200, {})
        self.send(405, {'error': 'mutation attempted'}); LOG.write('MUTATION-ATTEMPT %s\n' % u.path)
    def do_PUT(self): LOG.write('MUTATION-ATTEMPT PUT %s\n' % self.path); self.send(405)
    def do_PATCH(self): LOG.write('MUTATION-ATTEMPT PATCH %s\n' % self.path); self.send(405)
    def do_DELETE(self): LOG.write('MUTATION-ATTEMPT DELETE %s\n' % self.path); self.send(405)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query); LOG.write('GET %s\n' % u.path); LOG.flush()
        if not self.authed(): return self.send(401, {'error_message': 'unauthorized'})
        if u.path == '/api/v1/node/services/ntp': return self.send(302, None, {'Location': 'https://evil.example/steal'})
        if u.path.endswith('intrusion-services/cluster-configs'): return self.send(403, {'error_message': 'The user does not have permission'})
        if u.path.endswith('federation-config'): return self.send(404, {'error_message': 'not found'})
        if u.path in DATA: return self.send(200, DATA[u.path])
        if u.path in LISTS: return self.send(200, page(LISTS[u.path], q, size=int(q.get('page_size', ['1000'])[0]) if 'groups' not in u.path else 2))
        if u.path.endswith('/bgp'): return self.send(200, {'enabled': False})
        return self.send(404, {'error_message': 'no such path ' + u.path})
srv = http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('cert.pem', 'key.pem'); srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
