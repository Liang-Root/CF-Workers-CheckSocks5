import { connect } from 'cloudflare:sockets';
let 临时TOKEN, 永久TOKEN;
let parsedSocks5Address = {};
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0);
        const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 5)); // 每5分钟一个时间戳
        临时TOKEN = await 双重哈希(url.hostname + timestamp);
        永久TOKEN = env.TOKEN || 临时TOKEN;
        if (url.pathname.toLowerCase() === "/check") {
            if (env.TOKEN) {
                if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) {
                    return new Response(JSON.stringify({
                        status: "error",
                        message: `IP查询失败: 无效的TOKEN`,
                        timestamp: new Date().toISOString()
                    }, null, 4), {
                        status: 403,
                        headers: {
                            "content-type": "application/json; charset=UTF-8",
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }
            }
            if (url.searchParams.has("socks5")) {
                const 代理参数 = url.searchParams.get("socks5");
                return await 检测SOCKS5代理(代理参数);
            } else if (url.searchParams.has("http")) {
                const 代理参数 = url.searchParams.get("http");
                return await 检测HTTP代理(代理参数);
            } else if (url.searchParams.has("proxy")) {
                const 代理参数 = url.searchParams.get("proxy");
                if (代理参数.toLowerCase().startsWith("socks5://")) {
                    return await 检测SOCKS5代理(代理参数);
                } else if (代理参数.toLowerCase().startsWith("http://")) {
                    return await 检测HTTP代理(代理参数);
                }
            }
            // 如果没有提供有效的代理参数，返回错误响应
            return new Response(JSON.stringify({
                success: false,
                error: "请提供有效的代理参数：socks5、http 或 proxy"
            }, null, 2), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        } else if (url.pathname.toLowerCase() === '/ip-info') {
            if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) {
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: 无效的TOKEN`,
                    timestamp: new Date().toISOString()
                }, null, 4), {
                    status: 403,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
            const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
            try {
                const data = await getIpInfo(ip);
                // 返回数据给客户端，并添加CORS头
                return new Response(JSON.stringify(data, null, 4), {
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } catch (error) {
                console.error("IP查询失败:", error);
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: ${error.message}`,
                    code: "API_REQUEST_FAILED",
                    query: ip,
                    timestamp: new Date().toISOString(),
                    details: {
                        errorType: error.name,
                        stack: error.stack ? error.stack.split('\n')[0] : null
                    }
                }, null, 4), {
                    status: 500,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }
        if (env.TOKEN) {
            return new Response(await nginx(), {
                headers: {
                    'Content-Type': 'text/html; charset=UTF-8',
                },
            });
        } else if (env.URL302) return Response.redirect(env.URL302, 302);
        else if (env.URL) return await 代理URL(env.URL, url);
        else {
            const 网站图标 = env.ICO ? `<link rel="icon" href="${env.ICO}" type="image/x-icon">` : '';
            // 已修改版权信息
            const 网络备案 = env.BEIAN || `&copy; 2026 代理测试工具 .  ALL RIGHTS RESERVED . | 火山工作室`;
            let img = 'background: #ffffff;';
            if (env.IMG) {
                const imgs = await 整理(env.IMG);
                img = `background-image: url('${imgs[Math.floor(Math.random() * imgs.length)]}');`;
            }
            return await HTML(网站图标, 网络备案, img);
        }
    },
};

async function 检测HTTP代理(代理参数) {
    代理参数 = 代理参数.includes("://") ? 代理参数.split('://')[1] : 代理参数;
    console.log("http://", 代理参数);
    try {
        parsedSocks5Address = socks5AddressParser(代理参数);
    } catch (err) {
        let e = err;
        console.log(e.toString());
        return new Response(JSON.stringify({
            success: false,
            error: e.toString(),
            proxy: "http://" + 代理参数
        }, null, 2), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const result = await checkHttpProxy('members.3322.org', 80, '/dyndns/getip');
        const match = result.match(/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
        if (!match) throw new Error("无法从响应中提取落地IP");
        const 代理落地IP = match[1];

        // 直接调用IP查询逻辑，而不是发送HTTP请求
        const ipInfo = await getIpInfo(代理落地IP);

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify({
            success: true,
            proxy: "http://" + 代理参数,
            ...ipInfo
        }, null, 4), {
            headers: {
                "content-type": "application/json; charset=UTF-8",
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
            proxy: "http://" + 代理参数
        }, null, 2), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function 检测SOCKS5代理(代理参数) {
    代理参数 = 代理参数.includes("://") ? 代理参数.split('://')[1] : 代理参数;
    console.log("socks5://", 代理参数);
    try {
        parsedSocks5Address = socks5AddressParser(代理参数);
    } catch (err) {
        let e = err;
        console.log(e.toString());
        return new Response(JSON.stringify({
            success: false,
            error: e.toString(),
            proxy: "socks5://" + 代理参数
        }, null, 2), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const result = await checkSocks5Proxy('members.3322.org', 80, '/dyndns/getip');
        const match = result.match(/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
        if (!match) throw new Error("无法从响应中提取落地IP");
        const 代理落地IP = match[1];

        // 直接调用IP查询逻辑，而不是发送HTTP请求
        const ipInfo = await getIpInfo(代理落地IP);

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify({
            success: true,
            proxy: "socks5://" + 代理参数,
            ...ipInfo
        }, null, 4), {
            headers: {
                "content-type": "application/json; charset=UTF-8",
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
            proxy: "socks5://" + 代理参数
        }, null, 2), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

/**
 * 检测HTTP代理并发送HTTP请求
 */
async function checkHttpProxy(hostname, port, path) {
    const tcpSocket = await httpConnect(hostname, port);

    if (!tcpSocket) {
        throw new Error('HTTP代理连接失败');
    }

    try {
        const httpRequest = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`;
        const writer = tcpSocket.writable.getWriter();
        const encoder = new TextEncoder();

        await writer.write(encoder.encode(httpRequest));
        console.log('已发送HTTP请求');

        writer.releaseLock();

        const reader = tcpSocket.readable.getReader();
        const decoder = new TextDecoder();
        let response = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                response += decoder.decode(value, { stream: true });
            }
        } finally {
            reader.releaseLock();
        }

        await tcpSocket.close();
        return response;
    } catch (error) {
        try {
            await tcpSocket.close();
        } catch (closeError) {
            console.log('关闭连接时出错:', closeError);
        }
        throw error;
    }
}

/**
 * 检测SOCKS5代理并发送HTTP请求
 */
async function checkSocks5Proxy(hostname, port, path) {
    const tcpSocket = await socks5Connect(2, hostname, port);

    if (!tcpSocket) {
        throw new Error('SOCKS5连接失败');
    }

    try {
        const httpRequest = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`;
        const writer = tcpSocket.writable.getWriter();
        const encoder = new TextEncoder();

        await writer.write(encoder.encode(httpRequest));
        console.log('已发送HTTP请求');

        writer.releaseLock();

        const reader = tcpSocket.readable.getReader();
        const decoder = new TextDecoder();
        let response = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                response += decoder.decode(value, { stream: true });
            }
        } finally {
            reader.releaseLock();
        }

        await tcpSocket.close();
        return response;
    } catch (error) {
        try {
            await tcpSocket.close();
        } catch (closeError) {
            console.log('关闭连接时出错:', closeError);
        }
