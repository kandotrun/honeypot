#!/usr/bin/env python3
"""Inert WordPress decoy; all captured input stays in the JSONL log."""
import base64
import datetime as dt
import html
import io
import json
import os
import re
import ssl
import struct
import sys
import threading
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from xmlrpc.client import dumps as xmlrpc_dumps
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_LOCK = threading.Lock()
GENERATOR = '<meta name="generator" content="WordPress 6.4.2">'
PLUGIN_STABLE_VERSION = '2.3.1'
BODY_LOG_LIMIT = 16384
XMLRPC_CREDENTIAL_LIMIT = 20
CONFIG_BACKUP_NAMES = ('config.php.bak',)
JSON_CONFIG_NAMES = ('settings.json', 'appsettings.json', 'config.json')
COMPOSE_CONFIG_NAMES = ('docker-compose.yml', 'docker-compose.yaml', 'docker-compose.prod.yml', 'docker-compose.prod.yaml', 'docker-compose.override.yml', 'docker-compose.override.yaml')
SECRETS_CONFIG_NAMES = ('secrets.yaml', 'secrets.yml')
CONFIG_YAML_NAMES = ('.config.yaml',)
CONFIG_INI_NAMES = ('config.ini',)
CONFIG_JS_NAMES = ('config.js', 'env-config.js')
PARAMETERS_YML_NAMES = ('parameters.yml',)
AWS_YML_NAMES = ('aws.yml',)
DATABASE_YML_NAMES = ('database.yml',)
APPLICATION_YML_NAMES = ('application.yml',)
APPLICATION_PROPERTIES_NAMES = ('application.properties',)
ENV_EXAMPLE_NAMES = ('env.example',)
PACKAGE_CONFIG_NAMES = ('package.json',)
PACKAGE_LOCK_NAMES = ('package-lock.json',)
YARN_LOCK_NAMES = ('yarn.lock',)
COMPOSER_CONFIG_NAMES = ('composer.json',)
CLIENT_SECRETS_NAMES = ('client_secrets.json',)
CREDENTIALS_CONFIG_NAMES = ('credentials.json',)
GOOGLE_SERVICES_NAMES = ('google-services.json',)
GCP_SERVICE_ACCOUNT_NAMES = ('service-account.json', 'sa.json', 'gcp-key.json', 'gcp-credentials.json', 'gcp-sa.json', 'google-credentials.json', 'google-key.json', 'application_default_credentials.json', 'key.json', 'keyfile.json', 'firebase-adminsdk.json', 'firebase-key.json')
SECRETS_JSON_NAMES = ('secrets.json', 'env.json')
CREDENTIALS_XML_NAMES = ('credentials.xml',)
CONFIGURATION_NAMES = ('configuration.yaml', 'configuration.xml', 'configuration.json')
WEB_CONFIG_NAMES = ('web.config',)
DATABASE_CONFIG_NAMES = ('database.config',)
TERRAFORM_TFSTATE_NAMES = ('terraform.tfstate',)
README_MD_NAMES = ('readme.md',)
CROSSDOMAIN_XML_NAMES = ('crossdomain.xml',)
SETTINGS_PY_NAMES = ('settings.py',)
REQUIREMENTS_TXT_NAMES = ('requirements.txt',)
CREDENTIALS_INI_NAMES = ('credentials.ini',)
COMPOSER_LOCK_NAMES = ('composer.lock',)
DEBUG_LOG_NAMES = ('debug.log',)
SQL_DUMP_NAMES = ('dump.sql', 'backup.sql', 'db.sql', 'database.sql', 'mysql.sql')
ERROR_LOG_NAMES = ('error.log', 'php_error.log', 'php_errors.log')
LARAVEL_LOG_NAMES = ('laravel.log',)
APP_LOG_NAMES = ('app.log',)
SITE_ARCHIVE_NAMES = ('site.zip', 'backup.zip', 'www.zip')
GITLAB_CI_NAMES = ('.gitlab-ci.yml',)
DOCKERFILE_NAMES = ('dockerfile',)



# Public method names only; every authentication-dependent call remains a fault.
XMLRPC_METHODS = (
    'system.listMethods', 'system.getCapabilities', 'system.multicall',
    'wp.getUsersBlogs', 'wp.newPost', 'wp.editPost', 'wp.deletePost',
    'wp.getPost', 'wp.getPosts', 'wp.getPostType', 'wp.getPostTypes',
    'wp.getPostFormats', 'wp.getPostStatusList', 'wp.getPageStatusList',
    'wp.getPageTemplates', 'wp.getOptions', 'wp.setOptions',
    'wp.getUsers', 'wp.getUser', 'wp.getProfile', 'wp.editProfile',
    'wp.getCategories', 'wp.getTags', 'wp.newCategory', 'wp.deleteCategory',
    'wp.suggestCategories', 'wp.getTaxonomy', 'wp.getTaxonomies',
    'wp.getTerm', 'wp.getTerms', 'wp.newTerm', 'wp.editTerm', 'wp.deleteTerm',
    'wp.getPage', 'wp.getPages', 'wp.getPageList', 'wp.newPage',
    'wp.editPage', 'wp.deletePage', 'wp.getAuthors',
    'wp.getComment', 'wp.getComments', 'wp.newComment', 'wp.editComment',
    'wp.deleteComment', 'wp.getCommentCount', 'wp.getCommentStatusList',
    'wp.getMediaItem', 'wp.getMediaLibrary', 'wp.uploadFile',
    'wp.getRevisions', 'wp.restoreRevision',
    'blogger.getUsersBlogs', 'blogger.getUserInfo', 'blogger.getPost',
    'blogger.getRecentPosts', 'blogger.newPost', 'blogger.editPost',
    'blogger.deletePost', 'metaWeblog.newPost', 'metaWeblog.editPost',
    'metaWeblog.getPost', 'metaWeblog.getRecentPosts',
    'metaWeblog.getCategories', 'metaWeblog.newMediaObject',
    'metaWeblog.deletePost', 'metaWeblog.getUsersBlogs',
    'mt.getCategoryList', 'mt.getRecentPostTitles', 'mt.getPostCategories',
    'mt.setPostCategories', 'mt.supportedMethods', 'mt.supportedTextFilters',
    'mt.getTrackbackPings', 'mt.publishPost',
    'pingback.ping', 'pingback.extensions.getPingbacks',
    'demo.sayHello', 'demo.addTwoNumbers',
)


def xmlrpc_metadata(body):
    """Read only the primary method and direct multicall structs, never entities."""
    if '<!DOCTYPE' in body.upper() or '<!ENTITY' in body.upper():
        return {}
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return {}
    if root.tag != 'methodCall':
        return {}
    method = root.findtext('methodName', '').strip()
    metadata = {'xmlrpc_method': method} if method else {}
    if method == 'system.multicall':
        count = len(root.findall('./params/param/value/array/data/value/struct'))
        if count:
            metadata['xmlrpc_multicall_count'] = count
    return metadata


def xml_credentials(body):
    """Recognize positional WordPress XML-RPC arguments without executing XML."""
    if '<!DOCTYPE' in body.upper() or '<!ENTITY' in body.upper():
        return {}
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return {}
    pairs = []
    def collect(method, values):
        offset = 0 if method == 'wp.getUsersBlogs' else 1
        if method.startswith(('wp.', 'blogger.', 'metaWeblog.')):
            args = [v.find('string') for v in values]
            if len(args) > offset + 1 and all(x is not None for x in args[offset:offset + 2]):
                pair = [x.text or '' for x in args[offset:offset + 2]]
                if pair not in pairs:
                    pairs.append(pair)
    collect(root.findtext('methodName', ''), root.findall('./params/param/value'))
    for struct in root.findall('.//struct'):
        members = {m.findtext('name'): m.find('value') for m in struct.findall('member')}
        method = members.get('methodName')
        params = members.get('params')
        if method is not None and params is not None:
            collect(method.findtext('string', ''), params.findall('./array/data/value'))
    if not pairs:
        return {}
    # Scalar fields preserve the common single-call schema; a list retains up to 20 pairs.
    return {'xmlrpc_user': pairs[0][0], 'xmlrpc_pass': pairs[0][1],
            'xmlrpc_credentials': pairs[:XMLRPC_CREDENTIAL_LIMIT]}


def classify(method, path, query, headers, body):
    lower = urllib.parse.unquote(path).lower()
    if any(s in lower for s in ('.env', 'wp-config.php', 'phpinfo', 'eval-stdin.php',
                                'thinkphp', '/vendor/phpunit', 'shell', '.git/')) or lower in ('/.aws/credentials', '/.aws/config', '/.kube/config') or (
            '/wp-content/uploads' in lower and 'upload' in lower) or (
            lower.rsplit('/', 1)[-1] in CONFIG_BACKUP_NAMES + JSON_CONFIG_NAMES + COMPOSE_CONFIG_NAMES + SECRETS_CONFIG_NAMES + CONFIG_YAML_NAMES + CONFIG_INI_NAMES + CONFIG_JS_NAMES + PARAMETERS_YML_NAMES + AWS_YML_NAMES + DATABASE_YML_NAMES + APPLICATION_YML_NAMES + APPLICATION_PROPERTIES_NAMES + ENV_EXAMPLE_NAMES + PACKAGE_CONFIG_NAMES + PACKAGE_LOCK_NAMES + YARN_LOCK_NAMES + COMPOSER_CONFIG_NAMES + CLIENT_SECRETS_NAMES + CREDENTIALS_CONFIG_NAMES + GOOGLE_SERVICES_NAMES + GCP_SERVICE_ACCOUNT_NAMES + SECRETS_JSON_NAMES + CREDENTIALS_XML_NAMES + CONFIGURATION_NAMES + WEB_CONFIG_NAMES + DATABASE_CONFIG_NAMES + TERRAFORM_TFSTATE_NAMES + README_MD_NAMES + CROSSDOMAIN_XML_NAMES + SETTINGS_PY_NAMES + REQUIREMENTS_TXT_NAMES + CREDENTIALS_INI_NAMES + COMPOSER_LOCK_NAMES + DEBUG_LOG_NAMES + SQL_DUMP_NAMES + ERROR_LOG_NAMES + LARAVEL_LOG_NAMES + APP_LOG_NAMES + SITE_ARCHIVE_NAMES + GITLAB_CI_NAMES + DOCKERFILE_NAMES):
        return {'event': 'exploit_probe'}
    if (path == '/wp-login.php' and method in ('GET', 'HEAD', 'POST')
            and urllib.parse.parse_qs(query).get('action', [''])[0] == 'lostpassword'):
        fields = urllib.parse.parse_qs(body, keep_blank_values=True) if method == 'POST' else {}
        return {'event': 'lostpassword', 'lostpassword_user': fields.get('user_login', [''])[0]}
    if path == '/wp-login.php' and method == 'POST':
        fields = urllib.parse.parse_qs(body, keep_blank_values=True)
        return {'event': 'wp_login', 'username': fields.get('log', [''])[0],
                'password': fields.get('pwd', [''])[0]}
    if path == '/xmlrpc.php' and method == 'POST':
        return {'event': 'xmlrpc', **xml_credentials(body), **xmlrpc_metadata(body)}
    if method == 'POST' and (
            path in ('/wp-json/batch/v1', '/wp-json/batch/v1/',
                     '/index.php/wp-json/batch/v1', '/index.php/wp-json/batch/v1/')
            or (path in ('/', '/index.php') and (
                any(value.strip('/') == 'batch/v1' for value in
                    urllib.parse.parse_qs(query).get('rest_route', []))
                or ('rest_route' in body and '/batch/v1' in body)))):
        # Inspect counts only; subrequest URLs and credentials are never used.
        try:
            data = json.loads(body)
        except (ValueError, RecursionError):
            data = None
        if isinstance(data, dict) and isinstance(data.get('requests'), list):
            count = len(data['requests'])
        else:
            indices = set(re.findall(r'requests\[(\d+)\]', urllib.parse.unquote_plus(body)))
            count = len(indices) if indices else 1
        return {'event': 'rest_batch', 'batch_count': min(count, 20)}
    if path == '/wp-admin' or path.startswith('/wp-admin/'):
        return {'event': 'admin_probe'}
    for kind in ('plugin', 'theme'):
        match = re.match(r'/wp-content/' + kind + r's/([^/]+)(?:/|$)', path)
        if match:
            return {'event': kind + '_probe', kind: match.group(1)}
    if method in ('GET', 'HEAD'):
        if path in ('/feed', '/feed/', '/feed/rss2', '/feed/rss2/',
                    '/feed/rss', '/feed/rss/', '/comments/feed', '/comments/feed/',
                    '/feed/atom', '/feed/atom/', '/feed/rdf', '/feed/rdf/',
                    '/comments/feed/atom', '/comments/feed/atom/',
                    '/comments/feed/rdf', '/comments/feed/rdf/') or (
                path in ('/', '/index.php') and any(value in ('rss2', 'rss', 'atom', 'rdf')
                    for value in urllib.parse.parse_qs(query).get('feed', []))):
            return {'event': 'feed'}
        routes = {'/': 'page_home', '/index.php': 'page_home', '/wp-login.php': 'page_login',
                  '/xmlrpc.php': 'page_xmlrpc', '/wp-json': 'rest_index',
                  '/wp-json/': 'rest_index', '/wp-json/wp/v2': 'rest_index',
                  '/wp-json/wp/v2/': 'rest_index',
                  '/wp-json/wp/v2/users': 'rest_users',
                  '/wp-json/wp/v2/users/1': 'rest_users',
                  '/wp-json/wp/v2/posts': 'rest_posts',
                  '/wp-json/wp/v2/posts/1': 'rest_posts',
                  '/wp-json/wp/v2/pages': 'rest_pages',
                  '/wp-json/wp/v2/pages/2': 'rest_pages',
                  '/wp-json/wp/v2/types': 'rest_types',
                  '/wp-json/wp/v2/types/post': 'rest_types',
                  '/wp-json/wp/v2/types/page': 'rest_types',
                  '/wp-json/wp/v2/categories': 'rest_categories',
                  '/wp-json/wp/v2/categories/1': 'rest_categories',
                  '/wp-json/wp/v2/comments': 'rest_comments',
                  '/wp-json/wp/v2/comments/1': 'rest_comments',
                  '/wp-json/wp/v2/settings': 'rest_forbidden',
                  '/wp-json/wp/v2/themes': 'rest_forbidden',
                  '/wp-json/wp/v2/plugins': 'rest_forbidden'}
        if path in ('/', '/index.php'):
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            if 'rest_route' in params:
                rest_path = '/wp-json/' + params['rest_route'][0].strip('/')
                if rest_path in routes:
                    return {'event': routes[rest_path]}
                if re.fullmatch(r'/wp-json/wp/v2/types/([a-z0-9_-]+)', rest_path):
                    return {'event': 'rest_types'}
                match = re.fullmatch(r'/wp-json/wp/v2/(posts|pages|users|categories|comments)/[0-9]+', rest_path)
                if match:
                    return {'event': 'rest_' + match.group(1)}
        if (path == '/' and urllib.parse.parse_qs(query).get('author') == ['1']) or path in (
                '/author/admin/', '/author/admin'):
            return {'event': 'author_probe', 'author': 'admin'}
        if path in routes:
            return {'event': routes[path]}
        if re.fullmatch(r'/wp-json/wp/v2/types/([a-z0-9_-]+)', path):
            return {'event': 'rest_types'}
        match = re.fullmatch(r'/wp-json/wp/v2/(posts|pages|users|categories|comments)/[0-9]+', path)
        if match:
            return {'event': 'rest_' + match.group(1)}
    return {'event': 'http_request'}


def page(content):
    return ('<!doctype html><html><head><title>WordPress</title>' + GENERATOR +
            '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">'
            '<script src="/wp-includes/js/jquery/jquery.min.js"></script></head>'
            '<body><header><h1>My WordPress Blog</h1></header><main>' + content +
            '</main><footer>Proudly powered by WordPress</footer></body></html>')


def login(error=''):
    return page(error + '<h1>Log In</h1><form method="post" action="/wp-login.php">'
                '<label>Username <input name="log"></label>'
                '<label>Password <input type="password" name="pwd"></label>'
                '<input type="checkbox" name="remember-me" value="forever">Remember Me'
                '<input type="hidden" name="redirect_to" value="/wp-admin/">'
                '<input type="hidden" name="testcookie" value="1">'
                '<button type="submit">Log In</button></form>')


def lostpassword(error=''):
    return page(error + '<h1>Lost Password</h1>'
                '<p>Please enter your username or email address. You will receive a link '
                'to create a new password via email.</p>'
                '<form method="post" action="/wp-login.php?action=lostpassword">'
                '<label>Username or Email Address <input name="user_login"></label>'
                '<button type="submit">Get New Password</button></form>'
                '<a href="/wp-login.php">Log in</a>')


def response(method, path, event, query=''):
    kind = event['event']
    status, mime, headers = 200, 'text/html; charset=utf-8', {}
    content = page('<h1>Oops! That page can’t be found.</h1>')
    if kind == 'page_home':
        if (method in ('GET', 'HEAD') and path in ('/', '/index.php')
                and urllib.parse.parse_qs(query).get('p') == ['1']):
            status, headers['Location'], content = 301, '/hello-world/', ''
        elif (method in ('GET', 'HEAD') and path in ('/', '/index.php')
                and urllib.parse.parse_qs(query).get('page_id') == ['2']):
            status, headers['Location'], content = 301, '/sample-page/', ''
        else:
            content = page('<article><h2>Hello world!</h2><p>Welcome to WordPress.</p></article>'
                           '<article><h2>A beautiful autumn morning</h2></article>')
    elif kind == 'feed':
        if path in ('/comments/feed/rdf', '/comments/feed/rdf/'):
            mime = 'application/rss+xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
                       'xmlns="http://purl.org/rss/1.0/" '
                       'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                       '<channel rdf:about="http://localhost">'
                       '<title>Comments for My WordPress Blog</title>'
                       '<link>http://localhost</link>'
                       '<description>Just another WordPress site</description>'
                       '<items><rdf:Seq><rdf:li rdf:resource="http://localhost/?p=1#comment-1"/>'
                       '</rdf:Seq></items></channel>'
                       '<item rdf:about="http://localhost/?p=1#comment-1">'
                       '<title>Comment on Hello world!</title>'
                       '<link>http://localhost/?p=1#comment-1</link>'
                       '<dc:date>2023-12-12T00:00:00Z</dc:date>'
                       '<dc:creator>admin</dc:creator>'
                       '<description>Hi, this is a comment.</description>'
                       '</item></rdf:RDF>')
        elif path in ('/comments/feed/atom', '/comments/feed/atom/'):
            mime = 'application/atom+xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<feed xmlns="http://www.w3.org/2005/Atom">'
                       '<title>Comments for My WordPress Blog</title>'
                       '<subtitle>Just another WordPress site</subtitle>'
                       '<updated>2023-12-12T00:00:00Z</updated>'
                       '<link rel="alternate" href="http://localhost"/>'
                       '<id>http://localhost/comments/feed/atom/</id>'
                       '<link rel="self" type="application/atom+xml" href="http://localhost/comments/feed/atom/"/>'
                       '<generator uri="https://wordpress.org/" version="6.4.2">WordPress</generator>'
                       '<entry><author><name>admin</name></author>'
                       '<title>Comment on Hello world!</title>'
                       '<link rel="alternate" href="http://localhost/hello-world/"/>'
                       '<id>http://localhost/?p=1#comment-1</id>'
                       '<updated>2023-12-12T00:00:00Z</updated>'
                       '<published>2023-12-12T00:00:00Z</published>'
                       '<summary>Hi, this is a comment.</summary>'
                       '<content>Hi, this is a comment.</content></entry></feed>')
        elif path in ('/feed/atom', '/feed/atom/') or (
                path in ('/', '/index.php')
                and 'atom' in urllib.parse.parse_qs(query).get('feed', [])):
            mime = 'application/atom+xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<feed xmlns="http://www.w3.org/2005/Atom">'
                       '<title>My WordPress Blog</title>'
                       '<subtitle>Just another WordPress site</subtitle>'
                       '<updated>2023-12-12T00:00:00Z</updated>'
                       '<link rel="alternate" href="http://localhost"/>'
                       '<id>http://localhost/feed/atom/</id>'
                       '<link rel="self" type="application/atom+xml" href="http://localhost/feed/atom/"/>'
                       '<generator uri="https://wordpress.org/" version="6.4.2">WordPress</generator>'
                       '<entry><author><name>admin</name></author>'
                       '<title>Hello world!</title>'
                       '<link rel="alternate" href="http://localhost/hello-world/"/>'
                       '<id>http://localhost/?p=1</id>'
                       '<updated>2023-12-12T00:00:00Z</updated>'
                       '<published>2023-12-12T00:00:00Z</published>'
                       '<category term="Uncategorized"/>'
                       '<summary>Welcome to WordPress.</summary>'
                       '<content>Welcome to WordPress.</content></entry></feed>')
        elif path in ('/feed/rdf', '/feed/rdf/') or (
                path in ('/', '/index.php')
                and 'rdf' in urllib.parse.parse_qs(query).get('feed', [])):
            mime = 'application/rss+xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
                       'xmlns="http://purl.org/rss/1.0/" '
                       'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                       '<channel rdf:about="http://localhost">'
                       '<title>My WordPress Blog</title>'
                       '<link>http://localhost</link>'
                       '<description>Just another WordPress site</description>'
                       '<items><rdf:Seq><rdf:li rdf:resource="http://localhost/?p=1"/>'
                       '</rdf:Seq></items></channel>'
                       '<item rdf:about="http://localhost/?p=1">'
                       '<title>Hello world!</title><link>http://localhost/?p=1</link>'
                       '<dc:date>2023-12-12T00:00:00Z</dc:date>'
                       '<dc:creator>admin</dc:creator>'
                       '<description>Welcome to WordPress.</description>'
                       '</item></rdf:RDF>')
        else:
            mime = 'application/rss+xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">'
                       '<channel><title>My WordPress Blog</title>'
                       '<link>http://localhost</link>'
                       '<description>Just another WordPress site</description>'
                       '<language>en-US</language>'
                       '<generator>https://wordpress.org/?v=6.4.2</generator>'
                       '<lastBuildDate>Tue, 12 Dec 2023 00:00:00 +0000</lastBuildDate>'
                       '<item><title>Hello world!</title>'
                       '<link>http://localhost/?p=1</link>'
                       '<guid>http://localhost/?p=1</guid>'
                       '<pubDate>Tue, 12 Dec 2023 00:00:00 +0000</pubDate>'
                       '<dc:creator>admin</dc:creator><category>Uncategorized</category>'
                       '<description>Welcome to WordPress.</description>'
                       '</item></channel></rss>')
    elif kind == 'author_probe':
        if path == '/':
            status, headers['Location'], content = 302, '/author/admin/', ''
        else:
            content = page('<h1>admin</h1>'
                           '<article><h2>Hello world!</h2><p>Welcome to WordPress.</p></article>'
                           '<article><h2>A beautiful autumn morning</h2></article>')
    elif kind in ('page_login', 'wp_login'):
        error = ''
        if kind == 'wp_login':
            error = '<div id="login_error">Error: The password you entered for the username ' + html.escape(event['username']) + ' is incorrect.</div>'
        content = login(error)
        headers['Set-Cookie'] = 'wordpress_test_cookie=WP%20Cookie%20check; path=/'
    elif kind == 'lostpassword':
        if method == 'POST' and event['lostpassword_user'] == 'admin':
            content = login('<div class="message">Check your email for the confirmation link.</div>')
        else:
            error = ('<div id="login_error">Error: Invalid username or email address.</div>'
                     if method == 'POST' else '')
            content = lostpassword(error)
        headers['Set-Cookie'] = 'wordpress_test_cookie=WP%20Cookie%20check; path=/'
    elif kind == 'page_xmlrpc':
        mime, content = 'text/plain; charset=utf-8', 'XML-RPC server accepts POST requests only.'
        if (method in ('GET', 'HEAD') and path == '/xmlrpc.php'
                and 'rsd' in urllib.parse.parse_qs(query, keep_blank_values=True)):
            mime = 'text/xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<rsd version="1.0" xmlns="http://archipelago.phrasewise.com/rsd">\n'
                       '<service>\n'
                       '<engineName>WordPress</engineName>\n'
                       '<engineLink>https://wordpress.org/</engineLink>\n'
                       '<homePageLink>http://localhost</homePageLink>\n'
                       '<apis>\n'
                       '<api name="WordPress" blogID="1" preferred="true" apiLink="http://localhost/xmlrpc.php" />\n'
                       '<api name="Movable Type" blogID="1" preferred="false" apiLink="http://localhost/xmlrpc.php" />\n'
                       '<api name="MetaWeblog" blogID="1" preferred="false" apiLink="http://localhost/xmlrpc.php" />\n'
                       '<api name="Blogger" blogID="1" preferred="false" apiLink="http://localhost/xmlrpc.php" />\n'
                       '<api name="WP-API" blogID="1" preferred="false" apiLink="http://localhost/wp-json/" />\n'
                       '</apis>\n</service>\n</rsd>')
    elif kind == 'xmlrpc':
        mime = 'text/xml; charset=utf-8'
        content = '<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name><value><string>Incorrect username or password.</string></value></member></struct></value></fault></methodResponse>'
        xml_method = event.get('xmlrpc_method', '')
        if xml_method == 'system.listMethods':
            content = xmlrpc_dumps((list(XMLRPC_METHODS),), methodresponse=True)
        elif xml_method == 'system.getCapabilities':
            capabilities = {
                'xmlrpc': {'specUrl': 'http://www.xmlrpc.com/spec', 'specVersion': 1},
                'faults_interop': {
                    'specUrl': 'http://xmlrpc-epi.sourceforge.net/specs/rfc.fault_codes.php',
                    'specVersion': 20010516},
                'system.multicall': {
                    'specUrl': 'http://www.xmlrpc.com/discuss/msgReader$1208',
                    'specVersion': 1},
            }
            content = xmlrpc_dumps((capabilities,), methodresponse=True)
        elif xml_method == 'system.multicall':
            faults = [{'faultCode': 403,
                       'faultString': 'Incorrect username or password.'}
                      for _ in range(event.get('xmlrpc_multicall_count', 1))]
            content = xmlrpc_dumps((faults,), methodresponse=True)
    elif kind == 'rest_batch':
        mime = 'application/json; charset=utf-8'
        count = event['batch_count']
        if count == 0:
            status = 400
            data = {'code': 'rest_batch_not_request',
                    'message': 'No batch requests were provided.',
                    'data': {'status': 400}}
        else:
            status = 207
            data = {'responses': [
                {'body': {'code': 'rest_forbidden_context',
                          'message': 'Sorry, you are not allowed to do that.',
                          'data': {'status': 401}},
                 'status': 401,
                 'headers': {'Content-Type': 'application/json; charset=UTF-8'}}
                for _ in range(count)]}
        content = json.dumps(data)
    elif kind in ('rest_index', 'rest_users', 'rest_posts', 'rest_pages', 'rest_types',
                  'rest_categories', 'rest_comments', 'rest_forbidden'):
        mime = 'application/json; charset=utf-8'
        if kind == 'rest_index':
            data = {'name': 'My WordPress Blog', 'description': 'Just another WordPress site', 'url': 'http://localhost', 'namespaces': ['wp/v2'], 'routes': {
                '/wp/v2/' + route: {'methods': ['GET']} for route in (
                    'users', 'posts', 'pages', 'types', 'categories', 'comments',
                    'settings', 'themes', 'plugins')}}
            target = path
            if path in ('/', '/index.php'):
                params = urllib.parse.parse_qs(query, keep_blank_values=True)
                if 'rest_route' in params:
                    target = '/wp-json/' + params['rest_route'][0].strip('/')
            if target in ('/wp-json/wp/v2', '/wp-json/wp/v2/'):
                data = {'namespace': 'wp/v2', 'routes': data['routes'],
                        '_links': {'self': [{'href': '/wp-json/wp/v2/'}]}}
        elif kind == 'rest_users':
            data = [{'id': 1, 'name': 'admin', 'slug': 'admin', 'link': '/author/admin/', 'avatar_urls': {'96': '/wp-content/uploads/avatar.png'}, '_links': {'self': [{'href': '/wp-json/wp/v2/users/1'}]}}]
        elif kind == 'rest_posts':
            data = [{'id': 1, 'slug': 'hello-world', 'status': 'publish', 'type': 'post',
                     'title': {'rendered': 'Hello world!'},
                     'excerpt': {'rendered': 'Welcome to WordPress.'},
                     'author': 1, 'categories': [1],
                     '_links': {'self': [{'href': '/wp-json/wp/v2/posts/1'}]}}]
        elif kind == 'rest_pages':
            data = [{'id': 2, 'slug': 'sample-page',
                     'title': {'rendered': 'Sample Page'}, 'author': 1}]
        elif kind == 'rest_types':
            data = {'post': {'name': 'Posts', 'slug': 'post', 'rest_base': 'posts'},
                    'page': {'name': 'Pages', 'slug': 'page', 'rest_base': 'pages'}}
        elif kind == 'rest_categories':
            data = [{'id': 1, 'name': 'Uncategorized', 'slug': 'uncategorized', 'count': 1}]
        elif kind == 'rest_comments':
            data = [{'id': 1, 'post': 1, 'author_name': 'admin',
                     'content': {'rendered': 'Hi, this is a comment.'}}]
        else:
            status = 401
            data = {'code': 'rest_forbidden_context',
                    'message': 'Sorry, you are not allowed to do that.',
                    'data': {'status': 401}}
        single_paths = {
            'rest_posts': '/wp-json/wp/v2/posts/1',
            'rest_pages': '/wp-json/wp/v2/pages/2',
            'rest_users': '/wp-json/wp/v2/users/1',
            'rest_categories': '/wp-json/wp/v2/categories/1',
            'rest_comments': '/wp-json/wp/v2/comments/1'}
        target = path
        if path in ('/', '/index.php'):
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            if 'rest_route' in params:
                target = '/wp-json/' + params['rest_route'][0].strip('/')
        if kind in single_paths and target == single_paths[kind]:
            data = data[0]
        elif kind in single_paths and re.fullmatch(
                r'/wp-json/wp/v2/(posts|pages|users|categories|comments)/[0-9]+', target):
            status = 404
            code, message = {
                'rest_posts': ('rest_post_invalid_id', 'Invalid post ID.'),
                'rest_pages': ('rest_post_invalid_id', 'Invalid post ID.'),
                'rest_users': ('rest_user_invalid_id', 'Invalid user ID.'),
                'rest_categories': ('rest_term_invalid', "Term doesn't exist."),
                'rest_comments': ('rest_comment_invalid_id', 'Invalid comment ID.'),
            }[kind]
            data = {'code': code, 'message': message, 'data': {'status': 404}}
        elif kind == 'rest_types' and target in (
                '/wp-json/wp/v2/types/post', '/wp-json/wp/v2/types/page'):
            data = data[target.rsplit('/', 1)[-1]]
        elif kind == 'rest_types' and re.fullmatch(
                r'/wp-json/wp/v2/types/([a-z0-9_-]+)', target):
            status = 404
            data = {'code': 'rest_type_invalid', 'message': 'Invalid post type.',
                    'data': {'status': 404}}
        content = json.dumps(data)
    elif path == '/wp-admin/admin-ajax.php' and method in ('GET', 'HEAD', 'POST'):
        content = '0'
    elif path == '/wp-admin/js/password-strength-meter.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for password-strength-meter */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.passwordStrength = {};\n')
    elif path == '/wp-admin/js/user-profile.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for user-profile */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.userProfile = {};\n')
    elif path == '/wp-admin/js/common.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for common */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.common = {};\n')
    elif path == '/wp-admin/js/updates.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for updates */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.updates = {};\n')
    elif path == '/wp-admin/js/postbox.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for postbox */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.postbox = {};\n')
    elif path == '/wp-admin/js/dashboard.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for dashboard */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.dashboard = {};\n')
    elif path == '/wp-admin/js/editor.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for editor */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.editor = {};\n')
    elif path == '/wp-admin/js/xfn.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for xfn */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.xfn = {};\n')
    elif method == 'OPTIONS' and path == '/':
        status, headers['Allow'], content = 200, 'GET, POST, OPTIONS, HEAD', ''
    elif method == 'TRACE' and path == '/':
        status, headers['Allow'], content = 405, 'GET, POST, OPTIONS, HEAD', ''
    elif method == 'PROPFIND' and path == '/':
        status, headers['Allow'], content = 405, 'GET, POST, OPTIONS, HEAD', ''
    elif kind == 'admin_probe':
        status, headers['Location'], content = 302, '/wp-login.php', ''
    elif kind == 'plugin_probe' and path.rsplit('/', 1)[-1].lower() == 'readme.txt':
        mime = 'text/plain; charset=utf-8'
        content = ('=== ' + event['plugin'].title() + ' ===\n'
                   'Requires at least: 5.0\nTested up to: 6.4\nRequires PHP: 7.4\n'
                   'Stable tag: ' + PLUGIN_STABLE_VERSION + '\n'
                   'License: GPLv2 or later\n\n'
                   '== Description ==\nA WordPress plugin.\n')
    elif kind == 'plugin_probe' and path.rsplit('/', 1)[-1].lower() in (
            'change_log.txt', 'changelog.txt', 'changelog.md'):
        mime = 'text/plain; charset=utf-8'
        content = ('== Changelog ==\n\n'
                   '= ' + PLUGIN_STABLE_VERSION + ' - 2023-12-12 =\n'
                   '* Minor fixes and compatibility improvements.\n\n'
                   '= 2.3.0 - 2023-10-18 =\n'
                   '* General improvements and maintenance fixes.\n\n'
                   '= 2.2.0 - 2023-08-09 =\n'
                   '* Improved reliability and fixed minor display issues.\n')
    elif kind == 'theme_probe' and path.rsplit('/', 1)[-1].lower() == 'readme.txt':
        mime = 'text/plain; charset=utf-8'
        content = ('=== ' + event['theme'].title() + ' ===\n'
                   'Requires at least: 6.4\nTested up to: 6.4\nRequires PHP: 7.4\n'
                   'Stable tag: 1.0.0\n'
                   'License: GPLv2 or later\n\n'
                   '== Description ==\nA WordPress theme.\n')
    elif kind == 'theme_probe' and path.endswith('style.css'):
        mime, content = 'text/css; charset=utf-8', '/* Theme Name: WordPress Theme\nVersion: 1.0.0\n*/\n'
    elif path == '/wp-includes/js/jquery/jquery.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* jQuery v3.7.1 - synthetic decoy stub */\n'
                   'window.jQuery = {version: "3.7.1"};\n')
    elif path == '/wp-includes/js/jquery/jquery-migrate.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-migrate */\n'
                   'window.jQueryMigrate = {};\n')
    elif path == '/wp-includes/js/jquery/ui/core.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-core */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = {};\n')
    elif path == '/wp-includes/js/jquery/ui/tabs.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-tabs */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.tabs = {};\n')
    elif path == '/wp-includes/js/jquery/ui/mouse.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-mouse */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.mouse = {};\n')
    elif path == '/wp-includes/js/jquery/ui/widget.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-widget */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.widget = {};\n')
    elif path == '/wp-includes/js/jquery/ui/draggable.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-draggable */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.draggable = {};\n')
    elif path == '/wp-includes/js/jquery/ui/sortable.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-sortable */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.sortable = {};\n')
    elif path == '/wp-includes/js/jquery/ui/resizable.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-resizable */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.resizable = {};\n')
    elif path == '/wp-includes/js/jquery/ui/droppable.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-droppable */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.droppable = {};\n')
    elif path == '/wp-includes/js/jquery/ui/dialog.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-dialog */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.dialog = {};\n')
    elif path == '/wp-includes/js/jquery/ui/button.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-button */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.button = {};\n')
    elif path == '/wp-includes/js/jquery/ui/checkboxradio.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-checkboxradio */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.checkboxradio = {};\n')
    elif path == '/wp-includes/js/jquery/ui/controlgroup.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-controlgroup */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.controlgroup = {};\n')
    elif path == '/wp-includes/js/jquery/ui/accordion.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-accordion */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.accordion = {};\n')
    elif path == '/wp-includes/js/jquery/ui/autocomplete.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-autocomplete */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.autocomplete = {};\n')
    elif path == '/wp-includes/js/jquery/ui/datepicker.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-datepicker */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.datepicker = {};\n')
    elif path == '/wp-includes/js/jquery/ui/menu.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for jquery-ui-menu */\n'
                   'window.jQuery = window.jQuery || {};\n'
                   'window.jQuery.ui = window.jQuery.ui || {};\n'
                   'window.jQuery.ui.menu = {};\n')
    elif path == '/wp-includes/js/jquery/jquery.min.js.map' and method in ('GET', 'HEAD'):
        mime = 'application/json'
        content = json.dumps({'version': 3, 'file': 'jquery.min.js',
                              'sources': ['jquery-3.7.1.js'], 'names': [], 'mappings': ''})
    elif path == '/wp-includes/js/wp-embed.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-embed */\n'
                   'window.wp = window.wp || {};\n')
    elif path == '/wp-includes/js/wp-emoji-release.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-emoji-release */\n'
                   'window.wpEmoji = {};\n')
    elif path == '/wp-includes/js/wp-emoji-loader.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-emoji-loader */\n'
                   'window.wpEmojiLoader = {};\n')
    elif path == '/wp-includes/js/comment-reply.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for comment-reply */\n'
                   'window.commentReply = {};\n')
    elif path == '/wp-includes/js/underscore.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for underscore */\n'
                   'window._ = {};\n')
    elif path == '/wp-includes/js/backbone.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for backbone */\n'
                   'window.Backbone = {};\n')
    elif path == '/wp-includes/js/wp-util.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-util */\n'
                   'window.wpUtil = {};\n')
    elif path == '/wp-includes/js/wp-api.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-api */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.api = {};\n')
    elif path == '/wp-includes/js/api-request.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for api-request */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.apiRequest = {};\n')
    elif path == '/wp-includes/js/heartbeat.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for heartbeat */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.heartbeat = {};\n')
    elif path == '/wp-includes/js/wp-backbone.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-backbone */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.Backbone = {};\n')
    elif path == '/wp-includes/js/wp-a11y.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-a11y */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.a11y = {};\n')
    elif path == '/wp-includes/js/imagesloaded.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for imagesloaded */\n'
                   'window.imagesLoaded = {};\n')
    elif path == '/wp-includes/js/masonry.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for masonry */\n'
                   'window.Masonry = {};\n')
    elif path == '/wp-includes/js/hoverIntent.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for hoverIntent */\n'
                   'window.hoverIntent = {};\n')
    elif path == '/wp-includes/js/wp-pointer.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-pointer */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.pointer = {};\n')
    elif path == '/wp-includes/js/shortcode.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for shortcode */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.shortcode = {};\n')
    elif path == '/wp-includes/js/wp-lists.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-lists */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.lists = {};\n')
    elif path == '/wp-includes/js/wp-ajax-response.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-ajax-response */\n'
                   'window.wpAjax = {};\n')
    elif path == '/wp-includes/js/wp-sanitize.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-sanitize */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.sanitize = {};\n')
    elif path == '/wp-includes/js/utils.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for utils */\n'
                   'window.userSettings = {};\n')
    elif path == '/wp-includes/js/admin-bar.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for admin-bar */\n'
                   'window.wpAdminBar = {};\n')
    elif path == '/wp-includes/js/zxcvbn-async.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for zxcvbn-async */\n'
                   'window.zxcvbnAsync = {};\n')
    elif path == '/wp-includes/js/wp-auth-check.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-auth-check */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.authCheck = {};\n')
    elif path == '/wp-includes/js/wplink.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wplink */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wpLink = {};\n')
    elif path == '/wp-includes/js/clipboard.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for clipboard */\n'
                   'window.ClipboardJS = {};\n')
    elif path == '/wp-includes/js/quicktags.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for quicktags */\n'
                   'window.QTags = {};\n')
    elif path == '/wp-includes/js/zxcvbn.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for zxcvbn */\n'
                   'window.zxcvbn = {};\n')
    elif path == '/wp-includes/js/tw-sack.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for tw-sack */\n'
                   'window.twSack = {};\n')
    elif path == '/wp-includes/js/customize-base.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for customize-base */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.customize = {};\n')
    elif path == '/wp-includes/js/autosave.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for autosave */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.autosave = {};\n')
    elif path == '/wp-includes/js/colorpicker.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for colorpicker */\n'
                   'window.ColorPicker = {};\n')
    elif path == '/wp-includes/js/mediaelement/mediaelement-and-player.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-and-player */\n'
                   'window.MediaElementPlayer = {};\n')
    elif path == '/wp-includes/js/mediaelement/wp-mediaelement.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-mediaelement */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.mediaelement = {};\n')
    elif path == '/wp-includes/js/mediaelement/wp-playlist.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for wp-playlist */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.playlist = {};\n')
    elif path == '/wp-includes/js/mediaelement/mediaelement-migrate.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-migrate */\n'
                   'window.MediaElementMigrate = {};\n')
    elif path == '/wp-includes/js/mediaelement/renderers/vimeo.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-vimeo */\n'
                   'window.MediaElementVimeo = {};\n')
    elif path == '/wp-includes/js/mediaelement/renderers/youtube.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-youtube */\n'
                   'window.MediaElementYoutube = {};\n')
    elif path == '/wp-includes/js/mediaelement/renderers/dailymotion.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-dailymotion */\n'
                   'window.MediaElementDailymotion = {};\n')
    elif path == '/wp-includes/js/mediaelement/renderers/facebook.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-facebook */\n'
                   'window.MediaElementFacebook = {};\n')
    elif path == '/wp-includes/js/mediaelement/renderers/soundcloud.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-soundcloud */\n'
                   'window.MediaElementSoundcloud = {};\n')
    elif path == '/wp-includes/js/mediaelement/renderers/twitch.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for mediaelement-twitch */\n'
                   'window.MediaElementTwitch = {};\n')
    elif path == '/wp-includes/js/media-views.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for media-views */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.media = {};\n')
    elif path == '/wp-includes/js/media-models.min.js' and method in ('GET', 'HEAD'):
        mime = 'application/javascript'
        content = ('/* Synthetic decoy stub for media-models */\n'
                   'window.wp = window.wp || {};\n'
                   'window.wp.media = window.wp.media || {};\n'
                   'window.wp.media.model = {};\n')
    elif path == '/wp-includes/wlwmanifest.xml' and method in ('GET', 'HEAD'):
        mime = 'application/xml; charset=utf-8'
        content = ('<?xml version="1.0" encoding="utf-8" ?>\n'
                   '<manifest xmlns="http://schemas.microsoft.com/wlw/manifest/weblog">\n'
                   '<options>\n'
                   '<clientType>WordPress</clientType>\n'
                   '<supportsKeywords>Yes</supportsKeywords>\n'
                   '<supportsGetTags>Yes</supportsGetTags>\n'
                   '<supportsNewCategories>Yes</supportsNewCategories>\n'
                   '<supportsNewCategoriesInline>Yes</supportsNewCategoriesInline>\n'
                   '<supportsCommentPolicy>Yes</supportsCommentPolicy>\n'
                   '<supportsSlug>Yes</supportsSlug>\n'
                   '<supportsExcerpt>Yes</supportsExcerpt>\n'
                   '<supportsPages>Yes</supportsPages>\n'
                   '<supportsPageParent>Yes</supportsPageParent>\n'
                   '<supportsAuthor>Yes</supportsAuthor>\n'
                   '<supportsCustomDate>Yes</supportsCustomDate>\n'
                   '<supportsFeaturedImage>Yes</supportsFeaturedImage>\n'
                   '<supportsPostAsDraft>Yes</supportsPostAsDraft>\n'
                   '<supportsCustomFields>Yes</supportsCustomFields>\n'
                   '<supportsTrackbacks>Yes</supportsTrackbacks>\n'
                   '</options>\n'
                   '</manifest>\n')
    elif path == '/robots.txt' and method in ('GET', 'HEAD'):
        mime, content = 'text/plain; charset=utf-8', 'User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n'
    elif path == '/hello-world/' and method in ('GET', 'HEAD'):
        content = page('<article><h2>Hello world!</h2><p>Welcome to WordPress.</p></article>')
    elif path == '/sample-page/' and method in ('GET', 'HEAD'):
        content = page('<article><h2>Sample Page</h2><p>This is an example page.</p></article>')
    elif path == '/category/uncategorized/' and method in ('GET', 'HEAD'):
        content = page('<h1>Category: Uncategorized</h1><article><h2>Hello world!</h2><p>Welcome to WordPress.</p></article>')
    elif path == '/sitemap.xml' and method in ('GET', 'HEAD'):
        status, headers['Location'], content = 302, '/wp-sitemap.xml', ''
    elif path == '/wp-sitemap.xml' and method in ('GET', 'HEAD'):
        mime = 'text/xml; charset=utf-8'
        content = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                   '<sitemap><loc>http://localhost/wp-sitemap-posts-post-1.xml</loc>'
                   '<lastmod>2023-12-12T00:00:00+00:00</lastmod></sitemap>'
                   '<sitemap><loc>http://localhost/wp-sitemap-posts-page-1.xml</loc>'
                   '<lastmod>2023-12-12T00:00:00+00:00</lastmod></sitemap>'
                   '<sitemap><loc>http://localhost/wp-sitemap-taxonomies-category-1.xml</loc>'
                   '<lastmod>2023-12-12T00:00:00+00:00</lastmod></sitemap>'
                   '<sitemap><loc>http://localhost/wp-sitemap-users-1.xml</loc>'
                   '<lastmod>2023-12-12T00:00:00+00:00</lastmod></sitemap>'
                   '</sitemapindex>')
    elif path in ('/wp-sitemap-posts-post-1.xml', '/wp-sitemap-posts-page-1.xml',
                  '/wp-sitemap-taxonomies-category-1.xml', '/wp-sitemap-users-1.xml') and method in ('GET', 'HEAD'):
        loc = {'/wp-sitemap-posts-post-1.xml': 'http://localhost/hello-world/',
               '/wp-sitemap-posts-page-1.xml': 'http://localhost/sample-page/',
               '/wp-sitemap-taxonomies-category-1.xml': 'http://localhost/category/uncategorized/',
               '/wp-sitemap-users-1.xml': 'http://localhost/author/admin/'}[path]
        mime = 'text/xml; charset=utf-8'
        content = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                   '<url><loc>' + loc + '</loc>'
                   '<lastmod>2023-12-12T00:00:00+00:00</lastmod></url>'
                   '</urlset>')
    elif path in ('/.well-known/security.txt', '/security.txt') and method in ('GET', 'HEAD'):
        mime = 'text/plain; charset=utf-8'
        content = ('Contact: mailto:security@example.com\n'
                   'Expires: 2024-12-31T00:00:00Z\n'
                   'Preferred-Languages: en\n')
    elif path == '/readme.html' and method in ('GET', 'HEAD'):
        content = ('<!doctype html><html><head><title>WordPress ReadMe</title>'
                   '</head><body><h1>WordPress</h1><p>Version 6.4.2</p>'
                   '<h2>Installation: Famous 5-minute install</h2>'
                   '<p>Unpack the package, configure a database, and follow the '
                   'installation wizard to set up your site.</p>'
                   '<h2>System Requirements</h2><ul>'
                   '<li>PHP version 7.4 or greater.</li>'
                   '<li>MySQL version 5.7 or greater or MariaDB 10.4 or greater.</li>'
                   '</ul><h2>License</h2>'
                   '<p>WordPress is distributed under the GNU General Public License (GPL).</p>'
                   '</body></html>')
    elif path == '/license.txt' and method in ('GET', 'HEAD'):
        mime = 'text/plain; charset=utf-8'
        content = ('WordPress - Web publishing software\n'
                   '\n'
                   'Copyright WordPress contributors.\n'
                   '\n'
                   'WordPress is free software: you can redistribute it and/or modify\n'
                   'it under the terms of the GNU General Public License (GPL),\n'
                   'version 2 or, at your option, any later version.\n'
                   '\n'
                   'WordPress is distributed in the hope that it will be useful,\n'
                   'but WITHOUT ANY WARRANTY; without even the implied warranty of\n'
                   'MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n'
                   '\n'
                   'See the GNU General Public License for more details.\n')
    elif path == '/wp-cron.php' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/wp-includes/version.php' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/wp-includes/load.php' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/config.php' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/admin/config.php' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/config.dev.php' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/debug.php' and method in ('GET', 'HEAD'):
        content = '<!doctype html><html><head><title>Debug</title></head><body><h1>Debug</h1><table><tr><th>PHP Version</th><td>8.1.2</td></tr><tr><th>Server API</th><td>Apache 2.4.52 (Ubuntu)</td></tr><tr><th>DOCUMENT_ROOT</th><td>/var/www/html</td></tr></table></body></html>'
    elif path == '/server-status' and method in ('GET', 'HEAD'):
        status = 403
        content = ''
    elif path == '/wp-content/' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/wp-content/themes/' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/wp-content/themes/twentytwentyfour/' and method in ('GET', 'HEAD'):
        status = 403
        content = ''
    elif path == '/wp-content/plugins/' and method in ('GET', 'HEAD'):
        content = ''
    elif path == '/wp-content/uploads/' and method in ('GET', 'HEAD'):
        status = 403
        content = ''
    elif path == '/wp-includes/' and method in ('GET', 'HEAD'):
        status = 403
        content = ''
    elif path == '/wp-includes/js/' and method in ('GET', 'HEAD'):
        status = 403
        content = ''
    elif path == '/wp-includes/js/jquery/' and method in ('GET', 'HEAD'):
        status = 403
        content = ''
    elif path == '/wp-content/uploads/avatar.png' and method in ('GET', 'HEAD'):
        mime = 'image/png'
        content = base64.b64decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII=')
    elif path == '/favicon.ico' and method in ('GET', 'HEAD'):
        mime = 'image/x-icon'
        # ICO container with one synthetic transparent 1x1 PNG.
        png = base64.b64decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII=')
        content = (struct.pack('<HHH', 0, 1, 1)
                   + struct.pack('<BBBBHHII', 1, 1, 0, 0, 1, 32, len(png), 22)
                   + png)
    else:
        lower = urllib.parse.unquote(path).lower()
        if kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in SITE_ARCHIVE_NAMES:
            if method in ('GET', 'HEAD'):
                mime = 'application/zip'
                entries = (
                    ('index.html', '<!-- Synthetic decoy -->\n'
                     '<h2>Hello world!</h2><p>Welcome to WordPress.</p>\n'),
                    ('wp-config.php', '<?php\n// Synthetic decoy; no real credentials\n'
                     "define('DB_HOST', 'localhost');\n"
                     "define('DB_NAME', 'wordpress');\n"
                     "define('DB_USER', 'wp_user');\n"
                     "define('DB_PASSWORD', 'synthetic-decoy-password-not-real');\n"),
                )
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, 'w') as zipped:
                    for name, data in entries:
                        info = zipfile.ZipInfo(name, date_time=(2023, 12, 12, 0, 0, 0))
                        zipped.writestr(info, data.encode('utf-8'))
                content = archive.getvalue()
            else:
                status = 404
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CONFIG_BACKUP_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('<?php\n// Synthetic decoy; no real credentials\n'
                       "define('DB_HOST', 'localhost');\n"
                       "define('DB_NAME', 'wordpress');\n"
                       "define('DB_USER', 'wp_user');\n"
                       "define('DB_PASSWORD', 'synthetic-decoy-password-not-real');\n")
        elif kind == 'exploit_probe' and 'wp-config.php' in lower:
            status = 403
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in ERROR_LOG_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('[12-Dec-2023 00:00:00 UTC] PHP Notice: Synthetic decoy server error log; PHP 8.1.2\n'
                       '[12-Dec-2023 00:00:01 UTC] PHP Warning: Undefined array key "page" '
                       'in /var/www/html/wp-content/plugins/example/hooks.php on line 24\n'
                       '[12-Dec-2023 00:00:02 UTC] PHP Notice: Plugin hook called before initialization '
                       'in /var/www/html/wp-includes/functions.php on line 100\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in LARAVEL_LOG_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('[2023-12-12 00:00:00] production.NOTICE: Synthetic decoy Laravel application log\n'
                       '[2023-12-12 00:00:01] production.NOTICE: Routine maintenance completed\n'
                       '[2023-12-12 00:00:02] production.WARNING: Deprecated application configuration option\n'
                       '[2023-12-12 00:00:03] production.ERROR: RuntimeException: Example operation unavailable\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in APP_LOG_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('[2023-12-12 00:00:00] INFO: Synthetic decoy application log; application started\n'
                       '[2023-12-12 00:00:01] INFO: Routine request completed\n'
                       '[2023-12-12 00:00:02] WARNING: Deprecated application option\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in SQL_DUMP_NAMES:
            mime = 'application/sql; charset=utf-8'
            content = ('-- MySQL dump 10.13\n'
                       '-- Host: localhost    Database: wordpress\n'
                       '-- Server version 8.0\n'
                       '-- Synthetic decoy dump; generated 2023-12-12\n'
                       '\n'
                       '-- Table structure for table `wp_posts`\n'
                       'CREATE TABLE `wp_posts` (\n'
                       '  `ID` bigint unsigned NOT NULL,\n'
                       '  `post_title` text NOT NULL,\n'
                       '  `post_content` longtext NOT NULL,\n'
                       '  PRIMARY KEY (`ID`)\n'
                       ');\n'
                       "INSERT INTO `wp_posts` VALUES (1, 'Hello world!', 'Welcome to WordPress.');\n"
                       '\n'
                       '-- Table structure for table `wp_options`\n'
                       'CREATE TABLE `wp_options` (\n'
                       '  `option_name` varchar(191) NOT NULL,\n'
                       '  `option_value` longtext NOT NULL,\n'
                       '  PRIMARY KEY (`option_name`)\n'
                       ');\n'
                       "INSERT INTO `wp_options` VALUES ('siteurl', 'http://localhost'), "
                       "('blogname', 'My WordPress Blog');\n"
                       '\n'
                       '-- Dump completed on 2023-12-12\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in DEBUG_LOG_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('[12-Dec-2023 00:00:00 UTC] PHP Notice: Synthetic decoy log; PHP 8.1.2\n'
                       '[12-Dec-2023 00:00:01 UTC] PHP Warning: Undefined variable $hook_name '
                       'in /var/www/html/wp-content/plugins/example/hooks.php on line 24\n'
                       '[12-Dec-2023 00:00:02 UTC] PHP Notice: Plugin hook called before initialization '
                       'in /var/www/html/wp-includes/functions.php on line 100\n'
                       '[12-Dec-2023 00:00:03 UTC] WordPress database error: '
                       'You have an error in your SQL syntax for query SELECT '
                       'made by /var/www/html/wp-content/plugins/example/hooks.php\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in ENV_EXAMPLE_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy example configuration; no real credentials\n'
                       'APP_ENV=production\nAPP_DEBUG=false\n'
                       'DB_HOST=localhost\nDB_DATABASE=wordpress\nDB_USERNAME=wp_user\n'
                       'DB_PASSWORD=synthetic-decoy-password-not-real\n'
                       'APP_KEY=synthetic-decoy-app-key-not-real\n'
                       'API_KEY=synthetic-decoy-api-key-not-real\n'
                       'CACHE_DRIVER=file\nSESSION_DRIVER=file\n')
        elif kind == 'exploit_probe' and '.env' in lower:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy configuration; no real credentials\n'
                       'APP_ENV=production\nAPP_DEBUG=false\n'
                       'DB_HOST=localhost\nDB_DATABASE=wordpress\nDB_USERNAME=wp_user\n'
                       'DB_PASSWORD=synthetic-decoy-password-not-real\n'
                       'APP_KEY=synthetic-decoy-app-key-not-real\n'
                       'API_KEY=synthetic-decoy-api-key-not-real\n'
                       'CACHE_DRIVER=file\nSESSION_DRIVER=file\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in PACKAGE_CONFIG_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'name': 'wordpress-site', 'version': '1.0.0', 'private': True,
                'description': 'WordPress site',
                'scripts': {'start': 'node server.js'},
                'dependencies': {'express': '^4.18.2'},
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in PACKAGE_LOCK_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'name': 'wordpress-site', 'version': '1.0.0',
                'lockfileVersion': 3, 'requires': True,
                'packages': {
                    '': {
                        'name': 'wordpress-site', 'version': '1.0.0',
                        'dependencies': {'express': '^4.18.2'},
                    },
                    'node_modules/express': {
                        'version': '4.18.2',
                        'resolved': 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
                        'integrity': 'synthetic-decoy-integrity-not-real',
                    },
                },
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in YARN_LOCK_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# yarn lockfile v1\n'
                       '# Synthetic decoy lockfile\n\n'
                       '"express@^4.18.2":\n'
                       '  version "4.18.2"\n'
                       '  resolved "synthetic-decoy-resolved-not-real"\n'
                       '  integrity synthetic-decoy-integrity-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in COMPOSER_CONFIG_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'name': 'wordpress-site', 'type': 'project',
                'description': 'WordPress site',
                'require': {'php': '>=7.4', 'wordpress/core': '6.4.2'},
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CLIENT_SECRETS_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'web': {
                    'client_id': 'synthetic-decoy-client-id-not-real',
                    'client_secret': 'synthetic-decoy-client-secret-not-real',
                    'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                    'token_uri': 'https://oauth2.googleapis.com/token',
                    'redirect_uris': ['http://localhost/oauth2callback'],
                },
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CREDENTIALS_CONFIG_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'database': {'host': 'localhost', 'name': 'wordpress', 'user': 'wp_user',
                             'password': 'synthetic-decoy-password-not-real'},
                'api_key': 'synthetic-decoy-api-key-not-real',
                'secret_key': 'synthetic-decoy-secret-key-not-real',
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in GOOGLE_SERVICES_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'project_info': {
                    'project_number': '123456789012',
                    'project_id': 'synthetic-decoy-project',
                    'storage_bucket': 'synthetic-decoy-project.appspot.com',
                },
                'client': [{
                    'client_info': {
                        'mobilesdk_app_id': 'synthetic-decoy-app-id-not-real',
                        'android_client_info': {'package_name': 'com.example.wordpress'},
                    },
                    'oauth_client': [],
                    'api_key': [{'current_key': 'synthetic-decoy-api-key-not-real'}],
                    'services': {'appinvite_service': {'other_platform_oauth_client': []}},
                }],
                'configuration_version': '1',
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in GCP_SERVICE_ACCOUNT_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'type': 'service_account',
                'project_id': 'synthetic-decoy-project',
                'private_key_id': 'synthetic-decoy-private-key-id-not-real',
                'private_key': 'synthetic-decoy-private-key-not-real',
                'client_email': 'synthetic-decoy@synthetic-decoy-project.iam.gserviceaccount.com',
                'client_id': 'synthetic-decoy-client-id-not-real',
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
                'client_x509_cert_url': 'https://www.googleapis.com/robot/v1/metadata/x509/synthetic-decoy%40synthetic-decoy-project.iam.gserviceaccount.com',
                'universe_domain': 'googleapis.com',
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in SECRETS_JSON_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'database': {'host': 'localhost', 'name': 'wordpress', 'user': 'wp_user',
                             'password': 'synthetic-decoy-password-not-real'},
                'api_key': 'synthetic-decoy-api-key-not-real',
                'secret_key': 'synthetic-decoy-secret-key-not-real',
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CREDENTIALS_XML_NAMES:
            mime = 'application/xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<credentials><database><host>localhost</host>'
                       '<name>wordpress</name><user>wp_user</user>'
                       '<password>synthetic-decoy-password-not-real</password>'
                       '</database><api_key>synthetic-decoy-api-key-not-real</api_key>'
                       '<secret_key>synthetic-decoy-secret-key-not-real</secret_key>'
                       '</credentials>\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in REQUIREMENTS_TXT_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('Django==4.2.7\n'
                       'mysqlclient==2.2.0\n'
                       'gunicorn==21.2.0\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in SETTINGS_PY_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy settings; no real credentials\n'
                       'DEBUG = False\n'
                       "ALLOWED_HOSTS = ['localhost']\n"
                       "SECRET_KEY = 'synthetic-decoy-secret-key-not-real'\n"
                       'DATABASES = {\n'
                       "    'default': {\n"
                       "        'ENGINE': 'django.db.backends.mysql',\n"
                       "        'NAME': 'wordpress',\n"
                       "        'USER': 'wp_user',\n"
                       "        'HOST': 'localhost',\n"
                       "        'PASSWORD': 'synthetic-decoy-password-not-real',\n"
                       '    },\n'
                       '}\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CROSSDOMAIN_XML_NAMES:
            mime = 'application/xml'
            content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<cross-domain-policy>\n'
                       '<site-control permitted-cross-domain-policies="all"/>\n'
                       '<allow-access-from domain="*" secure="false"/>\n'
                       '</cross-domain-policy>\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in README_MD_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# WordPress Site\n'
                       '\n'
                       'A WordPress site and blog.\n'
                       '\n'
                       '## Installation\n'
                       'Install WordPress 6.4.2 and follow the installation wizard.\n'
                       '\n'
                       '## Requirements\n'
                       '- PHP 7.4+\n'
                       '- MySQL 5.7+\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in TERRAFORM_TFSTATE_NAMES:
            mime = 'application/json'
            content = json.dumps({
                'version': 4,
                'terraform_version': '1.5.7',
                'serial': 1,
                'lineage': 'synthetic-decoy-lineage-not-real',
                'outputs': {},
                'resources': [],
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in DATABASE_CONFIG_NAMES:
            mime = 'application/xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<configuration><connectionStrings>'
                       '<add name="WordPress" connectionString="Server=localhost;Database=wordpress;'
                       'User Id=wp_user;Password=synthetic-decoy-password-not-real" />'
                       '</connectionStrings><appSettings>'
                       '<add key="api_key" value="synthetic-decoy-api-key-not-real" />'
                       '<add key="secret" value="synthetic-decoy-secret-not-real" />'
                       '</appSettings></configuration>\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in WEB_CONFIG_NAMES:
            mime = 'application/xml; charset=utf-8'
            content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                       '<configuration><connectionStrings>'
                       '<add name="WordPress" connectionString="Server=localhost;Database=wordpress;'
                       'User Id=wp_user;Password=synthetic-decoy-password-not-real" />'
                       '</connectionStrings><appSettings>'
                       '<add key="ApiKey" value="synthetic-decoy-api-key-not-real" />'
                       '<add key="SecretKey" value="synthetic-decoy-secret-key-not-real" />'
                       '</appSettings></configuration>\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CONFIGURATION_NAMES:
            if lower.endswith('.json'):
                mime = 'application/json; charset=utf-8'
                content = json.dumps({
                    'database': {'host': 'localhost', 'name': 'wordpress', 'user': 'wp_user',
                                 'password': 'synthetic-decoy-password-not-real'},
                    'api_key': 'synthetic-decoy-api-key-not-real',
                    'secret_key': 'synthetic-decoy-secret-key-not-real',
                })
            elif lower.endswith('.xml'):
                mime = 'application/xml; charset=utf-8'
                content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                           '<configuration><database><host>localhost</host>'
                           '<name>wordpress</name><user>wp_user</user>'
                           '<password>synthetic-decoy-password-not-real</password>'
                           '</database><api_key>synthetic-decoy-api-key-not-real</api_key>'
                           '<secret_key>synthetic-decoy-secret-key-not-real</secret_key>'
                           '</configuration>\n')
            else:
                mime = 'text/plain; charset=utf-8'
                content = ('# Synthetic decoy configuration; no real credentials\n'
                           'database:\n'
                           '  host: localhost\n'
                           '  name: wordpress\n'
                           '  user: wp_user\n'
                           '  password: synthetic-decoy-password-not-real\n'
                           'api_key: synthetic-decoy-api-key-not-real\n'
                           'secret_key: synthetic-decoy-secret-key-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CREDENTIALS_INI_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('[database]\n'
                       'host=localhost\n'
                       'name=wordpress\n'
                       'user=wp_user\n'
                       'password=synthetic-decoy-password-not-real\n'
                       '\n'
                       '[credentials]\n'
                       'api_key=synthetic-decoy-api-key-not-real\n'
                       'secret_key=synthetic-decoy-secret-key-not-real\n')
        elif kind == 'exploit_probe' and lower == '/.aws/config':
            mime = 'text/plain; charset=utf-8'
            content = ('[default]\n'
                       'region = us-east-1\n'
                       'output = json\n')
        elif kind == 'exploit_probe' and lower == '/.kube/config':
            mime = 'text/plain; charset=utf-8'
            content = ('apiVersion: v1\n'
                       'kind: Config\n'
                       'clusters:\n'
                       '- cluster:\n'
                       '    server: https://localhost:6443\n'
                       '  name: synthetic-decoy-cluster\n'
                       'contexts:\n'
                       '- context:\n'
                       '    cluster: synthetic-decoy-cluster\n'
                       '    user: synthetic-decoy-user\n'
                       '  name: synthetic-decoy-context\n'
                       'current-context: synthetic-decoy-context\n'
                       'users:\n'
                       '- name: synthetic-decoy-user\n'
                       '  user:\n'
                       '    token: synthetic-decoy-token-not-real\n')
        elif kind == 'exploit_probe' and lower == '/.aws/credentials':
            mime = 'text/plain; charset=utf-8'
            content = ('[default]\n'
                       'aws_access_key_id = synthetic-decoy-access-key-not-real\n'
                       'aws_secret_access_key = synthetic-decoy-secret-key-not-real\n'
                       'region = us-east-1\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in COMPOSER_LOCK_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'content-hash': 'synthetic-decoy-content-hash-not-real',
                'packages': [{
                    'name': 'wordpress/core', 'version': '6.4.2',
                    'type': 'library', 'require': {'php': '>=7.4'},
                }],
                'packages-dev': [], 'aliases': [],
                'minimum-stability': 'stable',
                'platform': {'php': '>=7.4'}, 'plugin-api-version': '2.6.0',
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in JSON_CONFIG_NAMES:
            mime = 'application/json; charset=utf-8'
            content = json.dumps({
                'environment': 'synthetic-decoy',
                'database': {'host': 'localhost', 'name': 'synthetic-decoy-database',
                             'username': 'synthetic-decoy-user',
                             'password': 'synthetic-decoy-password-not-real'},
                'api': {'key': 'synthetic-decoy-api-key-not-real'},
            })
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in SECRETS_CONFIG_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy secrets configuration; no real credentials\n'
                       'database:\n'
                       '  host: localhost\n'
                       '  name: wordpress\n'
                       '  username: wp_user\n'
                       '  password: synthetic-decoy-password-not-real\n'
                       '  root_password: synthetic-decoy-root-password-not-real\n'
                       'api_key: synthetic-decoy-api-key-not-real\n'
                       'session_secret: synthetic-decoy-session-secret-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CONFIG_YAML_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy application configuration; no real credentials\n'
                       'app:\n'
                       '  env: production\n'
                       'database:\n'
                       '  host: localhost\n'
                       '  name: wordpress\n'
                       '  username: wp_user\n'
                       '  password: synthetic-decoy-password-not-real\n'
                       'api_key: synthetic-decoy-api-key-not-real\n'
                       'session_secret: synthetic-decoy-session-secret-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in PARAMETERS_YML_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy Symfony configuration; no real credentials\n'
                       'parameters:\n'
                       '  database_host: localhost\n'
                       '  database_name: wordpress\n'
                       '  database_user: wp_user\n'
                       '  database_password: synthetic-decoy-password-not-real\n'
                       '  secret: synthetic-decoy-secret-not-real\n'
                       '  api_key: synthetic-decoy-api-key-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in AWS_YML_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy AWS configuration; no real credentials\n'
                       'aws:\n'
                       '  region: us-east-1\n'
                       '  access_key_id: synthetic-decoy-access-key-not-real\n'
                       '  secret_access_key: synthetic-decoy-secret-access-key-not-real\n'
                       '  session_token: synthetic-decoy-session-token-not-real\n'
                       'database:\n'
                       '  host: localhost\n'
                       '  name: wordpress\n'
                       '  username: wp_user\n'
                       '  password: synthetic-decoy-password-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in DATABASE_YML_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy Rails configuration; no real credentials\n'
                       'production:\n'
                       '  adapter: mysql2\n'
                       '  encoding: utf8mb4\n'
                       '  database: wordpress\n'
                       '  username: wp_user\n'
                       '  host: localhost\n'
                       '  password: synthetic-decoy-password-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in APPLICATION_YML_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy Spring Boot configuration; no real credentials\n'
                       'spring:\n'
                       '  datasource:\n'
                       '    url: jdbc:mysql://localhost:3306/wordpress\n'
                       '    username: wp_user\n'
                       '    password: synthetic-decoy-password-not-real\n'
                       'server:\n'
                       '  port: 8080\n'
                       'api_key: synthetic-decoy-api-key-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in APPLICATION_PROPERTIES_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy Spring Boot configuration; no real credentials\n'
                       'spring.datasource.url=jdbc:mysql://localhost:3306/wordpress\n'
                       'spring.datasource.username=wp_user\n'
                       'spring.datasource.password=synthetic-decoy-password-not-real\n'
                       'server.port=8080\n'
                       'api_key=synthetic-decoy-api-key-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CONFIG_INI_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('[app]\n'
                       'env=production\n'
                       'api_key=synthetic-decoy-api-key-not-real\n'
                       'session_secret=synthetic-decoy-session-secret-not-real\n'
                       '\n'
                       '[database]\n'
                       'host=localhost\n'
                       'name=wordpress\n'
                       'username=wp_user\n'
                       'password=synthetic-decoy-password-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in CONFIG_JS_NAMES:
            mime = 'application/javascript'
            content = ('// Synthetic decoy configuration; no real credentials\n'
                       'const config = {\n'
                       "  apiUrl: 'http://localhost',\n"
                       "  database: {host: 'localhost', name: 'wordpress', user: 'wp_user',\n"
                       "    password: 'synthetic-decoy-password-not-real'},\n"
                       "  apiKey: 'synthetic-decoy-api-key-not-real',\n"
                       "  sessionSecret: 'synthetic-decoy-session-secret-not-real'\n"
                       '};\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in GITLAB_CI_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy GitLab CI configuration; no real credentials\n'
                       'stages:\n'
                       '  - build\n'
                       '  - test\n'
                       '  - deploy\n'
                       'variables:\n'
                       '  DB_HOST: localhost\n'
                       '  DB_NAME: wordpress\n'
                       '  DB_USER: wp_user\n'
                       '  DB_PASSWORD: synthetic-decoy-password-not-real\n'
                       '  DEPLOY_TOKEN: synthetic-decoy-deploy-token-not-real\n'
                       'build:\n'
                       '  stage: build\n'
                       '  script:\n'
                       '    - echo "Synthetic decoy build"\n'
                       'test:\n'
                       '  stage: test\n'
                       '  script:\n'
                       '    - echo "Synthetic decoy test"\n'
                       'deploy:\n'
                       '  stage: deploy\n'
                       '  script:\n'
                       '    - echo "Synthetic decoy deploy"\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in DOCKERFILE_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy Dockerfile; no real credentials\n'
                       'FROM wordpress:6.4.2-apache\n'
                       'WORKDIR /var/www/html\n'
                       'COPY . /var/www/html/\n'
                       'EXPOSE 80\n'
                       'ENV WORDPRESS_DB_HOST=localhost\n'
                       'ENV WORDPRESS_DB_NAME=wordpress\n'
                       'ENV WORDPRESS_DB_USER=wp_user\n'
                       'ENV WORDPRESS_DB_PASSWORD=synthetic-decoy-password-not-real\n')
        elif kind == 'exploit_probe' and lower.rsplit('/', 1)[-1] in COMPOSE_CONFIG_NAMES:
            mime = 'text/plain; charset=utf-8'
            content = ('# Synthetic decoy configuration; no real credentials\n'
                       'services:\n'
                       '  wordpress:\n'
                       '    image: wordpress:6.4.2-apache\n'
                       '    ports:\n'
                       '      - "80:80"\n'
                       '    environment:\n'
                       '      WORDPRESS_DB_HOST: db\n'
                       '      WORDPRESS_DB_NAME: wordpress\n'
                       '      WORDPRESS_DB_USER: wp_user\n'
                       '      WORDPRESS_DB_PASSWORD: synthetic-decoy-password-not-real\n'
                       '  db:\n'
                       '    image: mysql:8.0\n'
                       '    environment:\n'
                       '      MYSQL_DATABASE: wordpress\n'
                       '      MYSQL_USER: wp_user\n'
                       '      MYSQL_PASSWORD: synthetic-decoy-password-not-real\n'
                       '      MYSQL_ROOT_PASSWORD: synthetic-decoy-root-password-not-real\n'
                       '    volumes:\n'
                       '      - db_data:/var/lib/mysql\n'
                       'volumes:\n'
                       '  db_data:\n')
        elif (method in ('GET', 'HEAD') and lower.rsplit('/', 1)[-1] == 'info.php'
              and 'phpinfo' not in lower):
            content = ('<!doctype html><html><head><title>phpinfo()</title>'
                       '<style>body{font-family:sans-serif;color:#222;background:#fff}'
                       'table{border-collapse:collapse;width:80%;margin:20px auto}'
                       'td,th{border:1px solid #666;padding:6px;text-align:left}'
                       'th{background:#99c}td{background:#ddd}</style></head><body>'
                       '<table><tr><th colspan="2">PHP Version 8.1.2</th></tr>'
                       '<tr><td>Server API</td><td>Apache 2.4.52 (Ubuntu)</td></tr>'
                       '<tr><td>Loaded Modules</td><td>core, curl, gd, json, mbstring, '
                       'mysqli, openssl, xml, zip</td></tr>'
                       '<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>'
                       '</table></body></html>')
        elif (method in ('GET', 'HEAD') and lower.rsplit('/', 1)[-1] == 'test.php'
              and 'phpinfo' not in lower):
            content = ('<!doctype html><html><head><title>Test</title></head><body>'
                       '<h1>Test</h1><table>'
                       '<tr><th>PHP Version</th><td>8.1.2</td></tr>'
                       '<tr><th>Server API</th><td>Apache 2.4.52 (Ubuntu)</td></tr>'
                       '<tr><th>DOCUMENT_ROOT</th><td>/var/www/html</td></tr>'
                       '</table></body></html>')
        elif method in ('GET', 'HEAD') and lower.rsplit('/', 1)[-1] == 'server.js':
            mime = 'application/javascript'
            content = ('// Synthetic decoy configuration; no real credentials\n'
                       "const express = require('express');\n"
                       'const app = express();\n'
                       'const config = {\n'
                       "  database: {host: 'localhost', database: 'wordpress', user: 'wp_user',\n"
                       "    password: 'synthetic-decoy-password-not-real'},\n"
                       "  sessionSecret: 'synthetic-decoy-session-secret-not-real'\n"
                       '};\n'
                       "app.get('/', (req, res) => res.send('Hello World!'));\n"
                       'app.listen(3000);\n')
        else:
            status = 404
    return status, mime, headers, content if isinstance(content, bytes) else content.encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    server_version = 'Apache/2.4.52 (Ubuntu)'
    sys_version = ''
    timeout = 10

    def version_string(self):
        return self.server_version

    def log_message(self, *args):
        pass

    def __getattr__(self, name):
        if name.startswith('do_'):
            return self.handle_request
        raise AttributeError(name)

    def handle_request(self):
        body = b''
        try:
            length = max(0, int(self.headers.get('Content-Length', '0')))
        except ValueError:
            length = 0
        try:
            body = self.rfile.read(min(length, 65536))
        except (OSError, TimeoutError):
            pass
        decoded = body.decode('utf-8', errors='replace')
        path, _, query = self.path.partition('?')
        event = classify(self.command, path, query, self.headers, decoded)
        status, mime, headers, payload = response(self.command, path, event, query)
        record = {'ts': dt.datetime.now().astimezone().isoformat(),
                  'src_ip': self.client_address[0], 'method': self.command,
                  'path': path, 'query': query, 'user_agent': self.headers.get('User-Agent', ''),
                  **event, 'status': status, 'body': decoded[:BODY_LOG_LIMIT]}
        with LOG_LOCK:
            with open(os.environ.get('WP_LOG', '/data/wp.jsonl'), 'a', encoding='utf-8') as log:
                log.write(json.dumps(record, ensure_ascii=True) + '\n')
                log.flush()
        try:
            self.send_response(status)
            self.send_header('X-Powered-By', 'PHP/8.1.2')
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(payload)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(payload)
        except (OSError, TimeoutError):
            pass


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Disconnects and socket timeouts are expected on an internet decoy.
        if not isinstance(sys.exception(), (OSError, TimeoutError)):
            super().handle_error(request, client_address)


def main():
    log_path = os.environ.get('WP_LOG', '/data/wp.jsonl')
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    http = Server(('0.0.0.0', int(os.environ.get('WP_PORT', '8080'))), Handler)
    cert, key = os.environ.get('WP_CERT', '/certs/cert.pem'), os.environ.get('WP_KEY', '/certs/key.pem')
    if os.path.isfile(cert) and os.path.isfile(key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https = Server(('0.0.0.0', int(os.environ.get('WP_TLS_PORT', '8443'))), Handler)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
    else:
        print('HTTPS listener skipped: certificate or key file missing', file=sys.stderr, flush=True)
    try:
        http.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http.server_close()


if __name__ == '__main__':
    main()
