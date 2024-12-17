import { connect } from "cloudflare:sockets";

let userID = "";
let proxyIP = "";
let sub = "";
let subConverter = "SUBAPI.fxxk.dedyn.io";
let subConfig =
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini";
let subProtocol = "https";
let subEmoji = "true";
let socks5Address = "";
let parsedSocks5Address = {};
let enableSocks = false;

let fakeUserID;
let fakeHostName;
let noTLS = "false";
const expire = 4102329600;
let proxyIPs;
let socks5s;
let go2Socks5s = [
    "*ttvnw.net",
    "*tapecontent.net",
    "*cloudatacdn.com",
    "*.loadshare.org",
];
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;
let FileName = atob("ZWRnZXR1bm5lbA==");
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL = "";
let RproxyIP = "false";
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let time01 = 7;
let time02 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = "/?ed=2560";
let tiaoid;
let link = [];
let banHosts = [atob("c3BlZWQuY2xvdWRmbGFyZS5jb20=")];
export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get("User-Agent") || "null";
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                tiaoid = env.KEY || env.TOKEN || userID;
                time01 = Number(env.TIME) || time01;
                time02 = Number(env.UPTIME) || time02;
                const userIDs = await cetiaoid(tiaoid);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            }

            if (!userID) {
                return new Response(
                    "请设置你的UUID变量，或尝试重试部署，检查变量是否生效？",
                    {
                        status: 404,
                        headers: {
                            "Content-Type": "text/plain;charset=utf-8",
                        },
                    }
                );
            }
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const fakeUserIDMD5 = await shuangsha(`${userID}${timestamp}`);
            fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20),
            ].join("-");

            fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(
                13,
                19
            )}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await shoushi(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

            socks5Address = env.SOCKS5 || socks5Address;
            socks5s = await shoushi(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            socks5Address = socks5Address.split("//")[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await shoushi(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await shoushi(env.CFPORTS);
            if (env.BAN) banHosts = await shoushi(env.BAN);
            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    RproxyIP = env.RPROXYIP || "false";
                    enableSocks = true;
                } catch (err) {
                    let e = err;
                    console.log(e.toString());
                    RproxyIP = env.RPROXYIP || !proxyIP ? "true" : "false";
                    enableSocks = false;
                }
            } else {
                RproxyIP = env.RPROXYIP || !proxyIP ? "true" : "false";
            }

            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                if (env.ADD) addresses = await shoushi(env.ADD);
                if (env.ADDAPI) addressesapi = await shoushi(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await shoushi(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await shoushi(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await shoushi(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                ChatID = env.TGID || ChatID;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == "0") subEmoji = "false";
                if (env.LINK) link = await shoushi(env.LINK);
                sub = env.SUB || sub;
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = "http";
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                if (url.searchParams.has("sub") && url.searchParams.get("sub") !== "")
                    sub = url.searchParams.get("sub");
                if (url.searchParams.has("notls")) noTLS = "true";

                if (url.searchParams.has("proxyip")) {
                    path = `/?ed=2560&proxyip=${url.searchParams.get("proxyip")}`;
                    RproxyIP = "false";
                } else if (url.searchParams.has("socks5")) {
                    path = `/?ed=2560&socks5=${url.searchParams.get("socks5")}`;
                    RproxyIP = "false";
                } else if (url.searchParams.has("socks")) {
                    path = `/?ed=2560&socks5=${url.searchParams.get("socks")}`;
                    RproxyIP = "false";
                }

                const ul = url.pathname.toLowerCase();
                if (ul == "/") {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await dul(env.URL, url);
                    else
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                "content-type": "application/json",
                            },
                        });
                } else if (ul == `/${fakeUserID}`) {
                    const fakeConfig = await cepz(
                        userID,
                        request.headers.get("Host"),
                        sub,
                        "CF-Workers-SUB",
                        RproxyIP,
                        url,
                        env
                    );
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if (
                    url.pathname == `/${tiaoid}/edit` ||
                    ul == `/${userID}/edit`
                ) {
                    const html = await KV(request, env);
                    return html;
                } else if (url.pathname == `/${tiaoid}` || ul == `/${userID}`) {
                    await sendMessage(
                        `#获取订阅 ${FileName}`,
                        request.headers.get("CF-Connecting-IP"),
                        `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search
                        }</tg-spoiler>`
                    );
                    const whisinfo = await cepz(
                        userID,
                        request.headers.get("Host"),
                        sub,
                        UA,
                        RproxyIP,
                        url,
                        env
                    );
                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(
                        (((now - today.getTime()) / 86400000) * 24 * 1099511627776) / 2
                    );
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;

                    if (userAgent && userAgent.includes("mozilla")) {
                        return new Response(
                            `<div style="font-size:13px;">${whisinfo}</div>`,
                            {
                                status: 200,
                                headers: {
                                    "Content-Type": "text/html;charset=utf-8",
                                    "Profile-Update-Interval": "6",
                                    "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                    "Cache-Control": "no-store",
                                },
                            }
                        );
                    } else {
                        return new Response(`${whisinfo}`, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(
                                    FileName
                                )}`,
                                "Content-Type": "text/plain;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            },
                        });
                    }
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await dul(env.URL, url);
                    else
                        return new Response("不用怀疑！你UUID就是错的！！！", {
                            status: 404,
                        });
                }
            } else {
                socks5Address = url.searchParams.get("socks5") || socks5Address;
                if (new RegExp("/socks5=", "i").test(url.pathname))
                    socks5Address = url.pathname.split("5=")[1];
                else if (
                    new RegExp("/socks://", "i").test(url.pathname) ||
                    new RegExp("/socks5://", "i").test(url.pathname)
                ) {
                    socks5Address = url.pathname.split("://")[1].split("#")[0];
                    if (socks5Address.includes("@")) {
                        let userPassword = socks5Address.split("@")[0];
                        const base64Regex =
                            /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(":"))
                            userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.split("@")[1]}`;
                    }
                }

                if (socks5Address) {
                    try {
                        parsedSocks5Address = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        let e = err;
                        console.log(e.toString());
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                if (url.searchParams.has("proxyip")) {
                    proxyIP = url.searchParams.get("proxyip");
                    enableSocks = false;
                } else if (new RegExp("/proxyip=", "i").test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split("/proxyip=")[1];
                    enableSocks = false;
                } else if (new RegExp("/proxyip.", "i").test(url.pathname)) {
                    proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]
                        }`;
                    enableSocks = false;
                } else if (new RegExp("/pyip=", "i").test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split("/pyip=")[1];
                    enableSocks = false;
                }

                return await whisOWSH(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    },
};

async function whisOWSH(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (
    /** @type {string} */ info,
    /** @type {string | undefined} */ event
    ) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

    const readableWebSocketStream = makeReadableWebSocketStream(
        webSocket,
        earlyDataHeader,
        log
    );

    let remoteSocketWapper = {
        value: null,
    };
    let isDns = false;

    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (isDns) {
                        return await handleDNSQuery(chunk, webSocket, null, log);
                    }
                    if (remoteSocketWapper.value) {
                        const writer = remoteSocketWapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const {
                        hasError,
                        message,
                        addressType,
                        portRemote = 443,
                        addressRemote = "",
                        rawDataIndex,
                        whisV = new Uint8Array([0, 0]),
                        isUDP,
                    } = pwhisH(chunk, userID);
                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "
                        } `;
                    if (hasError) {
                        throw new Error(message);
                        return;
                    }
                    if (isUDP) {
                        if (portRemote === 53) {
                            isDns = true;
                        } else {
                            throw new Error("UDP 代理仅对 DNS（53 端口）启用");
                            return;
                        }
                    }
                    const whisRH = new Uint8Array([whisV[0], 0]);
                    const rawClientData = chunk.slice(rawDataIndex);

                    if (isDns) {
                        return handleDNSQuery(rawClientData, webSocket, whisRH, log);
                    }
                    if (!banHosts.includes(addressRemote)) {
                        log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
                        handleTCPOutBound(
                            remoteSocketWapper,
                            addressType,
                            addressRemote,
                            portRemote,
                            rawClientData,
                            webSocket,
                            whisRH,
                            log
                        );
                    } else {
                        throw new Error(
                            `黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`
                        );
                    }
                },
                close() {
                    log(`readableWebSocketStream 已关闭`);
                },
                abort(reason) {
                    log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("readableWebSocketStream 管道错误", err);
        });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function handleTCPOutBound(
    remoteSocket,
    addressType,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    whisRH,
    log
) {
    async function useSocks5Pattern(address) {
        if (
            go2Socks5s.includes(atob("YWxsIGlu")) ||
            go2Socks5s.includes(atob("Kg=="))
        )
            return true;
        return go2Socks5s.some((pattern) => {
            let regexPattern = pattern.replace(/\*/g, ".*");
            let regex = new RegExp(`^${regexPattern}$`, "i");
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false) {
        log(`connected to ${address}:${port}`);
        const tcpSocket = socks
            ? await socks5Connect(addressType, address, port, log)
            : connect({
                hostname: address,
                port: port,
            });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        if (enableSocks) {
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
        } else {
            if (!proxyIP || proxyIP == "") {
                proxyIP = atob(`UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==`);
            } else if (proxyIP.includes("]:")) {
                portRemote = proxyIP.split("]:")[1] || portRemote;
                proxyIP = proxyIP.split("]:")[0] || proxyIP;
            } else if (proxyIP.split(":").length === 2) {
                portRemote = proxyIP.split(":")[1] || portRemote;
                proxyIP = proxyIP.split(":")[0] || proxyIP;
            }
            if (proxyIP.includes(".tp"))
                portRemote = proxyIP.split(".tp")[1].split(".")[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
        }
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                safeCloseWebSocket(webSocket);
            });
        remoteSocketToWS(tcpSocket, webSocket, whisRH, null, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks)
        useSocks = await useSocks5Pattern(addressRemote);
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);

    remoteSocketToWS(tcpSocket, webSocket, whisRH, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;

    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            webSocketServer.addEventListener("error", (err) => {
                log("WebSocket 服务器发生错误");
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
        },

        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`可读流被取消，原因是 ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });

    return stream;
}

/**
 * 解析 维列斯 协议的头部数据
 * @param { ArrayBuffer} whisB 维列斯 协议的原始头部数据
 * @param {string} userID 用于验证的用户 ID
 * @returns {Object} 解析结果，包括是否有错误、错误信息、远程地址信息等
 */
function pwhisH(whisB, userID) {
    if (whisB.byteLength < 24) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }

    const version = new Uint8Array(whisB.slice(0, 1));

    let isValidUser = false;
    let isUDP = false;

    function isUserIDValid(userID, userIDLow, buffer) {
        const userIDArray = new Uint8Array(buffer.slice(1, 17));
        const userIDString = stringify(userIDArray);
        return userIDString === userID || userIDString === userIDLow;
    }

    isValidUser = isUserIDValid(userID, userIDLow, whisB);

    if (!isValidUser) {
        return {
            hasError: true,
            message: `invalid user ${new Uint8Array(whisB.slice(1, 17))}`,
        };
    }

    const optLength = new Uint8Array(whisB.slice(17, 18))[0];

    const command = new Uint8Array(
        whisB.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    if (command === 1) {
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = whisB.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        whisB.slice(addressIndex, addressIndex + 1)
    );

    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(
                whisB.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(
                whisB.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                whisB.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(
                whisB.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invild addressType is ${addressType}`,
            };
    }

    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        whisV: version,
        isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, whisRH, retry, log) {
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let whisH = whisRH;
    let hasIncomingData = false;

    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                },
                /**
                 * 处理每个数据块
                 * @param {Uint8Array} chunk 数据块
                 * @param {*} controller 控制器
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;

                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket.readyState is not open, maybe close");
                    }

                    if (whisH) {
                        webSocket.send(await new Blob([whisH, chunk]).arrayBuffer());
                        whisH = null;
                    } else {
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(
                        `remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`
                    );
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(`remoteSocketToWS has exception `, error.stack || error);
            safeCloseWebSocket(webSocket);
        });

    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer
 *
 * @param {string} base64Str Base64 编码的输入字符串
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} 返回解码后的 ArrayBuffer 或错误
 */
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");

        const decode = atob(base64Str);

        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));

        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

/**
 * 这不是真正的 UUID 验证，而是一个简化的版本
 * @param {string} uuid 要验证的 UUID 字符串
 * @returns {boolean} 如果字符串匹配 UUID 格式则返回 true，否则返回 false
 */
function isValidUUID(uuid) {
    const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (
            socket.readyState === WS_READY_STATE_OPEN ||
            socket.readyState === WS_READY_STATE_CLOSING
        ) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * 快速地将字节数组转换为 UUID 字符串，不进行有效性检查
 * 这是一个底层函数，直接操作字节，不做任何验证
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} UUID 字符串
 */
function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        "-" +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        "-" +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        "-" +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        "-" +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

/**
 * 将字节数组转换为 UUID 字符串，并验证其有效性
 * 这是一个安全的函数，它确保返回的 UUID 格式正确
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} 有效的 UUID 字符串
 * @throws {TypeError} 如果生成的 UUID 字符串无效
 */
function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
    }
    return uuid;
}

/**
 * 处理 DNS 查询的函数
 * @param {ArrayBuffer} udpChunk - 客户端发送的 DNS 查询数据
 * @param {ArrayBuffer} whisRH - 维列斯 协议的响应头部数据
 * @param {(string)=> void} log - 日志记录函数
 */
async function handleDNSQuery(udpChunk, webSocket, whisRH, log) {
    try {
        const dnsServer = "8.8.4.4";
        const dnsPort = 53;

        let whisH = whisRH;

        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`连接到 ${dnsServer}:${dnsPort}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(
            new WritableStream({
                async write(chunk) {
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        if (whisH) {
                            webSocket.send(await new Blob([whisH, chunk]).arrayBuffer());
                            whisH = null;
                        } else {
                            webSocket.send(chunk);
                        }
                    }
                },
                close() {
                    log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`);
                },
                abort(reason) {
                    console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason);
                },
            })
        );
    } catch (error) {
        console.error(`handleDNSQuery 函数发生异常，错误信息: ${error.message}`);
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 2: 域名, 3: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({
        hostname,
        port,
    });


    const socksGreeting = new Uint8Array([5, 2, 0, 2]);

    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    log("已发送 SOCKS5 问候消息");

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;
    if (res[0] !== 0x05) {
        log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("服务器不接受任何认证方法");
        return;
    }

    if (res[1] === 0x02) {
        log("SOCKS5 服务器需要认证");
        if (!username || !password) {
            log("请提供用户名和密码");
            return;
        }
        const authRequest = new Uint8Array([
            1,
            username.length,
            ...encoder.encode(username),
            password.length,
            ...encoder.encode(password),
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 服务器认证失败");
            return;
        }
    }


    let DSTADDR;
    switch (addressType) {
        case 1:
            DSTADDR = new Uint8Array([1, ...addressRemote.split(".").map(Number)]);
            break;
        case 2:
            DSTADDR = new Uint8Array([
                3,
                addressRemote.length,
                ...encoder.encode(addressRemote),
            ]);
            break;
        case 3:
            DSTADDR = new Uint8Array([
                4,
                ...addressRemote
                    .split(":")
                    .flatMap((x) => [
                        parseInt(x.slice(0, 2), 16),
                        parseInt(x.slice(2), 16),
                    ]),
            ]);
            break;
        default:
            log(`无效的地址类型: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([
        5,
        1,
        0,
        ...DSTADDR,
        portRemote >> 8,
        portRemote & 0xff,
    ]);
    await writer.write(socksRequest);
    log("已发送 SOCKS5 请求");

    res = (await reader.read()).value;
    if (res[1] === 0x00) {
        log("SOCKS5 连接已建立");
    } else {
        log("SOCKS5 连接建立失败");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

/**
 * SOCKS5 代理地址解析器
 * 此函数用于解析 SOCKS5 代理地址字符串，提取出用户名、密码、主机名和端口号
 *
 * @param {string} address SOCKS5 代理地址，格式可以是：
 *   - "username:password@hostname:port" （带认证）
 *   - "hostname:port" （不需认证）
 *   - "username:password@[ipv6]:port" （IPv6 地址需要用方括号括起来）
 */
function socks5AddressParser(address) {
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error(
                '无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式'
            );
        }
        [username, password] = formers;
    }

    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error("无效的 SOCKS 地址格式：端口号必须是数字");
    }

    hostname = latters.join(":");

    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error(
            "无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]"
        );
    }

    return {
        username,
        password,
        hostname,
        port,
    };
}

/**
 * 恢复被伪装的信息
 * 这个函数用于将内容中的假用户ID和假主机名替换回真实的值
 *
 * @param {string} content 需要处理的内容
 * @param {string} userID 真实的用户ID
 * @param {string} hostName 真实的主机名
 * @param {boolean} isBase64 内容是否是Base64编码的
 * @returns {string} 恢复真实信息后的内容
 */
function hfwzxx(content, userID, hostName, isBase64) {
    if (isBase64) content = atob(content);

    content = content
        .replace(new RegExp(fakeUserID, "g"), userID)
        .replace(new RegExp(fakeHostName, "g"), hostName);

    if (isBase64) content = btoa(content);

    return content;
}

/**
 * 双重MD5哈希函数
 * 这个函数对输入文本进行两次MD5哈希，增强安全性
 * 第二次哈希使用第一次哈希结果的一部分作为输入
 *
 * @param {string} texts 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的小写十六进制字符串
 */
async function shuangsha(texts) {
    const bmq = new TextEncoder();

    const onesha = await crypto.subtle.digest("MD5", bmq.encode(texts));
    const oneshaarr = Array.from(new Uint8Array(onesha));
    const onehex = oneshaarr
        .map((bits) => bits.toString(16).padStart(2, "0"))
        .join("");

    const twosha = await crypto.subtle.digest(
        "MD5",
        bmq.encode(onehex.slice(7, 27))
    );
    const twoshaarr = Array.from(new Uint8Array(twosha));
    const twohex = twoshaarr
        .map((bits) => bits.toString(16).padStart(2, "0"))
        .join("");

    return twohex.toLowerCase();
}

async function dul(durl, murl) {
    const ulist = await shoushi(durl);
    const wurl = ulist[Math.floor(Math.random() * ulist.length)];

    let jurl = new URL(wurl);
    console.log(jurl);
    let XY = jurl.protocol.slice(0, -1) || "https";
    let HH = jurl.hostname;
    let ulname = jurl.pathname;
    let cxarg = jurl.search;

    if (ulname.charAt(ulname.length - 1) == "/") {
        ulname = ulname.slice(0, -1);
    }
    ulname += murl.pathname;

    let nurl = `${XY}://${HH}${ulname}${cxarg}`;

    let xyy = await fetch(nurl);

    let xxy = new Response(xyy.body, {
        status: xyy.status,
        statusText: xyy.statusText,
        headers: xyy.headers,
    });

    xxy.headers.set("X-New-URL", nurl);

    return xxy;
}

const what = atob("ZG14bGMzTT0=");
function pzinfo(UUID, ymdz) {
    const xylx = atob(what);

    const bm = FileName;
    let dz = ymdz;
    let dk = 443;

    const UID = UUID;
    const jmfs = "none";

    const csXY = "ws";
    const wzym = ymdz;
    const ul = path;

    let csaq = ["tls", true];
    const SNI = ymdz;
    const zw = "randomized";

    if (ymdz.includes(".workers.dev")) {
        dz = atob("dmlzYS5jbg==");
        dk = 80;
        csaq = ["", false];
    }

    const WTR =
        `${xylx}://${UID}@${dz}:${dk}\u003f\u0065\u006e\u0063\u0072\u0079` +
        "p" +
        `${atob("dGlvbj0=") + jmfs
        }\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${csaq[0]
        }&sni=${SNI}&fp=${zw}&type=${csXY}&host=${wzym}&path=${encodeURIComponent(
            ul
        )}#${encodeURIComponent(bm)}`;
    const gogogo = `- {name: ${FileName}, server: ${dz}, port: ${dk}, type: ${xylx}, uuid: ${UID}, tls: ${csaq[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: true, servername: ${wzym}, client-fingerprint: ${zw}, network: ${csXY}, ws-opts: {path: "${ul}", headers: {${wzym}}}}`;
    return [WTR, gogogo];
}

let subParams = ["sub", "base64", "b64", "clash", "singbox", "sb"];
const cmad = decodeURIComponent(
    atob(
        "dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM="
    )
);
/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function cepz(userID, hostName, sub, UA, RproxyIP, _url, env) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await shoushi(sub);
        if (subs.length > 1) sub = subs[0];
    } else {
        if (env.KV) {
            await qydzlist(env);
            const gooddzlist = await env.KV.get("ADD.txt");
            if (gooddzlist) {
                const gooddzarr = await shoushi(gooddzlist);
                const fldz = {
                    jkdz: new Set(),
                    linkdz: new Set(),
                    gooddz: new Set(),
                };

                for (const ys of gooddzarr) {
                    if (ys.startsWith("https://")) {
                        fldz.jkdz.add(ys);
                    } else if (ys.includes("://")) {
                        fldz.linkdz.add(ys);
                    } else {
                        fldz.gooddz.add(ys);
                    }
                }

                addressesapi = [...fldz.jkdz];
                link = [...fldz.linkdz];
                addresses = [...fldz.gooddz];
            }
        }

        if (
            addresses.length +
            addressesapi.length +
            addressesnotls.length +
            addressesnotlsapi.length +
            addressescsv.length ==
            0
        ) {
            let cfips = [
                "103.21.244.0/23",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "172.64.0.0/14",
                "103.21.244.0/23",
                "104.16.0.0/14",
                "104.24.0.0/15",
                "141.101.64.0/19",
                "172.64.0.0/14",
                "188.114.96.0/21",
                "190.93.240.0/21",
            ];

            function generateRandomIPFromCIDR(cidr) {
                const [base, mask] = cidr.split("/");
                const baseIP = base.split(".").map(Number);
                const subnetMask = 32 - parseInt(mask, 10);
                const maxHosts = Math.pow(2, subnetMask) - 1;
                const randomHost = Math.floor(Math.random() * maxHosts);

                const randomIP = baseIP.map((octet, index) => {
                    if (index < 2) return octet;
                    if (index === 2)
                        return (
                            (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255)
                        );
                    return (octet & (255 << subnetMask)) + (randomHost & 255);
                });

                return randomIP.join(".");
            }
            addresses = addresses.concat("127.0.0.1:1234#CFnat");
            if (hostName.includes(".workers.dev")) {
                addressesnotls = addressesnotls.concat(
                    cfips.map((cidr) => generateRandomIPFromCIDR(cidr) + "#CF随机节点")
                );
            } else {
                addresses = addresses.concat(
                    cfips.map((cidr) => generateRandomIPFromCIDR(cidr) + "#CF随机节点")
                );
            }
        }
    }

    const uuid = _url.pathname == `/${tiaoid}` ? tiaoid : userID;
    const userAgent = UA.toLowerCase();
    const Config = pzinfo(userID, hostName);
    const v2ray = Config[0];
    const clash = Config[1];
    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
            try {
                const response = await fetch(proxyhostsURL);

                if (!response.ok) {
                    console.error(
                        "获取地址时出错:",
                        response.status,
                        response.statusText
                    );
                    return;
                }

                const text = await response.text();
                const lines = text.split("\n");
                const nonEmptyLines = lines.filter((line) => line.trim() !== "");

                proxyhosts = proxyhosts.concat(nonEmptyLines);
            } catch (error) {
            }
        }
        if (proxyhosts.length != 0)
            proxyhost =
                proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
    }

    if (
        userAgent.includes("mozilla") &&
        !subParams.some((_searchParams) => _url.searchParams.has(_searchParams))
    ) {
        const newSocks5s = socks5s.map((socks5Address) => {
            if (socks5Address.includes("@")) return socks5Address.split("@")[1];
            else if (socks5Address.includes("//"))
                return socks5Address.split("//")[1];
            else return socks5Address;
        });

        let socks5List = "";
        if (go2Socks5s.length > 0 && enableSocks) {
            socks5List = `${decodeURIComponent(
                "SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20"
            )}`;
            if (
                go2Socks5s.includes(atob("YWxsIGlu")) ||
                go2Socks5s.includes(atob("Kg=="))
            )
                socks5List += `${decodeURIComponent(
                    "%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F"
                )}<br>`;
            else
                socks5List += `<br>&nbsp;&nbsp;${go2Socks5s.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
        }

        let dyq = "<br>";
        if (sub) {
            if (enableSocks)
                dyq += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>${socks5List}`;
            else if (proxyIP && proxyIP != "")
                dyq += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
            else if (RproxyIP == "true")
                dyq += `CFCDN（访问方式）: 自动获取ProxyIP<br>`;
            else
                dyq += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
            dyq += `<br>SUB（优选订阅生成器）: ${sub}`;
        } else {
            if (enableSocks)
                dyq += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>${socks5List}`;
            else if (proxyIP && proxyIP != "")
                dyq += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
            else
                dyq += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
            let ifKV = "";
            if (env.KV) ifKV = ` <a href='${_url.pathname}/edit'>编辑优选列表</a>`;
            dyq += `<br>您的订阅内容由 内置 addresses/ADD* 参数变量提供${ifKV}<br>`;
            if (addresses.length > 0)
                dyq += `ADD（TLS优选域名&IP）: <br>&nbsp;&nbsp;${addresses.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
            if (addressesnotls.length > 0)
                dyq += `ADDNOTLS（noTLS优选域名&IP）: <br>&nbsp;&nbsp;${addressesnotls.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
            if (addressesapi.length > 0)
                dyq += `ADDAPI（TLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesapi.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
            if (addressesnotlsapi.length > 0)
                dyq += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesnotlsapi.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
            if (addressescsv.length > 0)
                dyq += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: <br>&nbsp;&nbsp;${addressescsv.join(
                    "<br>&nbsp;&nbsp;"
                )}<br>`;
        }

        if (tiaoid && _url.pathname !== `/${tiaoid}`) dyq = "";
        else
            dyq += `<br>SUBAPI（订阅转换后端）: ${subProtocol}://${subConverter}<br>SUBCONFIG（订阅转换配置文件）: ${subConfig}`;
        const dtUID =
            uuid != userID
                ? `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME（动态UUID有效时间）: ${time01} 天<br>UPTIME（动态UUID更新时间）: ${time02} 时（北京时间）<br><br>`
                : `${userIDTime}`;
        const jdinfo = `
			################################################################<br>
			Subscribe / sub 订阅地址, 支持 Base64、clash-meta、sing-box 订阅格式<br>
			---------------------------------------------------------------<br>
			自适应订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}</a><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sub')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sub</a><br>
			<br>
			Base64订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?b64</a><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?base64')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?base64</a><br>
			<br>
			clash订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?clash</a><br>
			<br>
			singbox订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sb</a><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?singbox')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?singbox</a><br>
			<br>
			<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">实用订阅技巧∨</a></strong><br>
				<div id="noticeContent" class="notice-content" style="display: none;">
					<strong>1.</strong> 如您使用的是 PassWall、SSR+ 等路由插件，推荐使用 <strong>Base64订阅地址</strong> 进行订阅；<br>
					<br>
					<strong>2.</strong> 快速切换 <a href='${atob(
            "aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg=="
        )}'>优选订阅生成器</a> 至：sub.google.com，您可将"?sub=sub.google.com"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br>
					<br>
					<strong>3.</strong> 快速更换 PROXYIP 至：proxyip.fxxk.dedyn.io:443，您可将"?proxyip=proxyip.fxxk.dedyn.io:443"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp; https://${proxyhost}${hostName}/${uuid}<strong>?proxyip=proxyip.fxxk.dedyn.io:443</strong><br>
					<br>
					<strong>4.</strong> 快速更换 SOCKS5 至：user:password@127.0.0.1:1080，您可将"?socks5=user:password@127.0.0.1:1080"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?socks5=user:password@127.0.0.1:1080</strong><br>
					<br>
					<strong>5.</strong> 如需指定多个参数则需要使用'&'做间隔，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.fxxk.dedyn.io<br>
				</div>
			<script>
			function copyToClipboard(text) {
				navigator.clipboard.writeText(text).then(() => {
					alert('已复制到剪贴板');
				}).catch(err => {
					console.error('复制失败:', err);
				});
			}

			function toggleNotice() {
				const noticeContent = document.getElementById('noticeContent');
				const noticeToggle = document.getElementById('noticeToggle');
				if (noticeContent.style.display === 'none') {
					noticeContent.style.display = 'block';
					noticeToggle.textContent = '实用订阅技巧∧';
				} else {
					noticeContent.style.display = 'none'; 
					noticeToggle.textContent = '实用订阅技巧∨';
				}
			}
			</script>
			---------------------------------------------------------------<br>
			################################################################<br>
			${FileName} 配置信息<br>
			---------------------------------------------------------------<br>
			${dtUID}HOST: ${hostName}<br>
			UUID: ${userID}<br>
			FKID: ${fakeUserID}<br>
			UA: ${UA}<br>
			${dyq}<br>
			---------------------------------------------------------------<br>
			################################################################<br>
			v2ray<br>
			---------------------------------------------------------------<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('${v2ray}')" style="color:blue;text-decoration:underline;cursor:pointer;">${v2ray}</a><br>
			---------------------------------------------------------------<br>
			################################################################<br>
			clash-meta<br>
			---------------------------------------------------------------<br>
			${clash}<br>
			---------------------------------------------------------------<br>
			################################################################<br>
			${cmad}
			`;
        return jdinfo;
    } else {
        if (typeof fetch != "function") {
            return "Error: fetch is not available in this environment.";
        }

        let newAddressesapi = [];
        let newAddressescsv = [];
        let newAddressesnotlsapi = [];
        let newAddressesnotlscsv = [];

        if (hostName.includes(".workers.dev")) {
            noTLS = "true";
            fakeHostName = `${fakeHostName}.workers.dev`;
            newAddressesnotlsapi = await shoushigoodlist(addressesnotlsapi);
            newAddressesnotlscsv = await shoushics("FALSE");
        } else if (hostName.includes(".pages.dev")) {
            fakeHostName = `${fakeHostName}.pages.dev`;
        } else if (
            hostName.includes("worker") ||
            hostName.includes("notls") ||
            noTLS == "true"
        ) {
            noTLS = "true";
            fakeHostName = `notls${fakeHostName}.net`;
            newAddressesnotlsapi = await shoushigoodlist(addressesnotlsapi);
            newAddressesnotlscsv = await shoushics("FALSE");
        } else {
            fakeHostName = `${fakeHostName}.xyz`;
        }
        console.log(`虚假HOST: ${fakeHostName}`);
        let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID + atob("JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=") + RproxyIP
            }&path=${encodeURIComponent(path)}`;
        let isBase64 = true;

        if (!sub || sub == "") {
            if (hostName.includes("workers.dev")) {
                if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
                    try {
                        const response = await fetch(proxyhostsURL);

                        if (!response.ok) {
                            console.error(
                                "获取地址时出错:",
                                response.status,
                                response.statusText
                            );
                            return;
                        }

                        const text = await response.text();
                        const lines = text.split("\n");
                        const nonEmptyLines = lines.filter((line) => line.trim() !== "");

                        proxyhosts = proxyhosts.concat(nonEmptyLines);
                    } catch (error) {
                        console.error("获取地址时出错:", error);
                    }
                }
                proxyhosts = [...new Set(proxyhosts)];
            }

            newAddressesapi = await shoushigoodlist(addressesapi);
            newAddressescsv = await shoushics("TRUE");
            url = `https://${hostName}/${fakeUserID + _url.search}`;
            if (
                hostName.includes("worker") ||
                hostName.includes("notls") ||
                noTLS == "true"
            ) {
                if (_url.search) url += "&notls";
                else url += "?notls";
            }
            console.log(`虚假订阅: ${url}`);
        }

        if (!userAgent.includes("CF-Workers-SUB".toLowerCase())) {
            if (
                (userAgent.includes("clash") && !userAgent.includes("nekobox")) ||
                (_url.searchParams.has("clash") && !userAgent.includes("subconverter"))
            ) {
                url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(
                    url
                )}&insert=false&config=${encodeURIComponent(
                    subConfig
                )}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (
                userAgent.includes("sing-box") ||
                userAgent.includes("singbox") ||
                ((_url.searchParams.has("singbox") || _url.searchParams.has("sb")) &&
                    !userAgent.includes("subconverter"))
            ) {
                url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(
                    url
                )}&insert=false&config=${encodeURIComponent(
                    subConfig
                )}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            }
        }

        try {
            let content;
            if ((!sub || sub == "") && isBase64 == true) {
                content = await celocaldy(
                    fakeHostName,
                    fakeUserID,
                    noTLS,
                    newAddressesapi,
                    newAddressescsv,
                    newAddressesnotlsapi,
                    newAddressesnotlscsv
                );
            } else {
                const response = await fetch(url, {
                    headers: {
                        "User-Agent": UA + atob("IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ=="),
                    },
                });
                content = await response.text();
            }

            if (_url.pathname == `/${fakeUserID}`) return content;

            return hfwzxx(content, userID, hostName, isBase64);
        } catch (error) {
            console.error("Error fetching content:", error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function shoushigoodlist(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";

    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, 2000);

    try {
        const responses = await Promise.allSettled(
            api.map((apiUrl) =>
                fetch(apiUrl, {
                    method: "get",
                    headers: {
                        Accept: "text/html,application/xhtml+xml,application/xml;",
                        "User-Agent": atob("Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1"),
                    },
                    signal: controller.signal,
                }).then((response) =>
                    response.ok ? response.text() : Promise.reject()
                )
            )
        );

        for (const [index, response] of responses.entries()) {
            if (response.status === "fulfilled") {
                const content = await response.value;

                const lines = content.split(/\r?\n/);
                let jdbz = "";
                let csdk = "443";

                if (lines[0].split(",").length > 3) {
                    const idMatch = api[index].match(/id=([^&]*)/);
                    if (idMatch) jdbz = idMatch[1];

                    const portMatch = api[index].match(/port=([^&]*)/);
                    if (portMatch) csdk = portMatch[1];

                    for (let i = 1; i < lines.length; i++) {
                        const columns = lines[i].split(",")[0];
                        if (columns) {
                            newapi += `${columns}:${csdk}${jdbz ? `#${jdbz}` : ""}\n`;
                            if (api[index].includes("proxyip=true"))
                                proxyIPPool.push(`${columns}:${csdk}`);
                        }
                    }
                } else {
                    if (api[index].includes("proxyip=true")) {
                        proxyIPPool = proxyIPPool.concat(
                            (await shoushi(content))
                                .map((item) => {
                                    const baseItem = item.split("#")[0] || item;
                                    if (baseItem.includes(":")) {
                                        const port = baseItem.split(":")[1];
                                        if (!httpsPorts.includes(port)) {
                                            return baseItem;
                                        }
                                    } else {
                                        return `${baseItem}:443`;
                                    }
                                    return null;
                                })
                                .filter(Boolean)
                        );
                    }
                    newapi += content + "\n";
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        clearTimeout(timeout);
    }

    const newAddressesapi = await shoushi(newapi);

    return newAddressesapi;
}

async function shoushics(tls) {
    if (!addressescsv || addressescsv.length === 0) {
        return [];
    }

    let newAddressescsv = [];

    for (const csvUrl of addressescsv) {
        try {
            const response = await fetch(csvUrl);

            if (!response.ok) {
                console.error(
                    "获取CSV地址时出错:",
                    response.status,
                    response.statusText
                );
                continue;
            }

            const text = await response.text();
            let lines;
            if (text.includes("\r\n")) {
                lines = text.split("\r\n");
            } else {
                lines = text.split("\n");
            }

            const header = lines[0].split(",");
            const tlsIndex = header.indexOf("TLS");

            const ipAddressIndex = 0;
            const portIndex = 1;
            const dataCenterIndex = tlsIndex + remarkIndex;

            if (tlsIndex === -1) {
                console.error("CSV文件缺少必需的字段");
                continue;
            }

            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(",");
                const speedIndex = columns.length - 1;
                if (
                    columns[tlsIndex].toUpperCase() === tls &&
                    parseFloat(columns[speedIndex]) > DLS
                ) {
                    const ipAddress = columns[ipAddressIndex];
                    const port = columns[portIndex];
                    const dataCenter = columns[dataCenterIndex];

                    const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                    newAddressescsv.push(formattedAddress);
                    if (
                        csvUrl.includes("proxyip=true") &&
                        columns[tlsIndex].toUpperCase() == "true" &&
                        !httpsPorts.includes(port)
                    ) {
                        proxyIPPool.push(`${ipAddress}:${port}`);
                    }
                }
            }
        } catch (error) {
            console.error("获取CSV地址时出错:", error);
            continue;
        }
    }

    return newAddressescsv;
}

function celocaldy(
    host,
    UUID,
    noTLS,
    newAddressesapi,
    newAddressescsv,
    newAddressesnotlsapi,
    newAddressesnotlscsv
) {
    const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
    addresses = addresses.concat(newAddressesapi);
    addresses = addresses.concat(newAddressescsv);
    let notlsresponseBody;
    if (noTLS == "true") {
        addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
        addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
        const uniqueAddressesnotls = [...new Set(addressesnotls)];

        notlsresponseBody = uniqueAddressesnotls
            .map((address) => {
                let port = "-1";
                let addressid = address;

                const match = addressid.match(regex);
                if (!match) {
                    if (address.includes(":") && address.includes("#")) {
                        const parts = address.split(":");
                        address = parts[0];
                        const subParts = parts[1].split("#");
                        port = subParts[0];
                        addressid = subParts[1];
                    } else if (address.includes(":")) {
                        const parts = address.split(":");
                        address = parts[0];
                        port = parts[1];
                    } else if (address.includes("#")) {
                        const parts = address.split("#");
                        address = parts[0];
                        addressid = parts[1];
                    }

                    if (addressid.includes(":")) {
                        addressid = addressid.split(":")[0];
                    }
                } else {
                    address = match[1];
                    port = match[2] || port;
                    addressid = match[3] || address;
                }

                const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
                if (!isValidIPv4(address) && port == "-1") {
                    for (let httpPort of httpPorts) {
                        if (address.includes(httpPort)) {
                            port = httpPort;
                            break;
                        }
                    }
                }
                if (port == "-1") port = "80";

                let wzym = host;
                let zzul = path;
                let jdbz = "";
                const xylx = atob(what);

                const whisL = `${xylx}://${UUID}@${address}:${port +
                    atob("P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==") +
                    wzym
                    }&path=${encodeURIComponent(zzul)}#${encodeURIComponent(
                        addressid + jdbz
                    )}`;

                return whisL;
            })
            .join("\n");
    }

    const uniqueAddresses = [...new Set(addresses)];

    const responseBody = uniqueAddresses
        .map((address) => {
            let port = "-1";
            let addressid = address;

            const match = addressid.match(regex);
            if (!match) {
                if (address.includes(":") && address.includes("#")) {
                    const parts = address.split(":");
                    address = parts[0];
                    const subParts = parts[1].split("#");
                    port = subParts[0];
                    addressid = subParts[1];
                } else if (address.includes(":")) {
                    const parts = address.split(":");
                    address = parts[0];
                    port = parts[1];
                } else if (address.includes("#")) {
                    const parts = address.split("#");
                    address = parts[0];
                    addressid = parts[1];
                }

                if (addressid.includes(":")) {
                    addressid = addressid.split(":")[0];
                }
            } else {
                address = match[1];
                port = match[2] || port;
                addressid = match[3] || address;
            }

            if (!isValidIPv4(address) && port == "-1") {
                for (let httpsPort of httpsPorts) {
                    if (address.includes(httpsPort)) {
                        port = httpsPort;
                        break;
                    }
                }
            }
            if (port == "-1") port = "443";

            let wzym = host;
            let zzul = path;
            let jdbz = "";
            const matchingProxyIP = proxyIPPool.find((proxyIP) =>
                proxyIP.includes(address)
            );
            if (matchingProxyIP) zzul += `&proxyip=${matchingProxyIP}`;

            if (proxyhosts.length > 0 && wzym.includes(".workers.dev")) {
                zzul = `/${wzym}${zzul}`;
                wzym = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
                jdbz = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
            }

            const xylx = atob(what);
            const whisL = `${xylx}://${UUID}@${address}:${port + atob("P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ==") + wzym
                }&fp=random&type=ws&host=${wzym}&path=${encodeURIComponent(
                    zzul
                )}#${encodeURIComponent(addressid + jdbz)}`;

            return whisL;
        })
        .join("\n");

    let base64Response = responseBody;
    if (noTLS == "true") base64Response += `\n${notlsresponseBody}`;
    if (link.length > 0) base64Response += "\n" + link.join("\n");
    return btoa(base64Response);
}

async function shoushi(contents) {
    var recontent = contents.replace(/[	|"'\r\n]+/g, ",").replace(/,+/g, ",");

    if (recontent.charAt(0) == ",") recontent = recontent.slice(1);
    if (recontent.charAt(recontent.length - 1) == ",")
        recontent = recontent.slice(0, recontent.length - 1);

    const dzarr = recontent.split(",");

    return dzarr;
}

async function sendMessage(type, ip, add_data = "") {
    if (!BotToken || !ChatID) return;

    try {
        let msg = "";
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.ok) {
            const ipInfo = await response.json();
            msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
        } else {
            msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
        }

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(
            msg
        )}`;
        return fetch(url, {
            method: "GET",
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;",
                "Accept-Encoding": "gzip, deflate, br",
                "User-Agent": "Mozilla/5.0 Chrome/90.0.4430.72",
            },
        });
    } catch (error) {
        console.error("Error sending message:", error);
    }
}

function isValidIPv4(address) {
    const ipv4Regex =
        /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(address);
}

function cetiaoid(my) {
    const sqpy = 8; 
    const srq = new Date(2007, 6, 7, time02, 0, 0); 
    const yzhm = 1000 * 60 * 60 * 24 * time01;

    function getnowz() {
        const dnow = new Date();
        const tznow = new Date(dnow.getTime() + sqpy * 60 * 60 * 1000);
        const timec = Number(tznow) - Number(srq);
        return Math.ceil(timec / yzhm);
    }

    function ceID(jcstr) {
        const shahc = new TextEncoder().encode(jcstr);
        return crypto.subtle.digest("SHA-256", shahc).then((sha) => {
            const shaarr = Array.from(new Uint8Array(sha));
            const slsha = shaarr.map((b) => b.toString(16).padStart(2, "0")).join("");
            return `${slsha.substr(0, 8)}-${slsha.substr(8, 4)}-4${slsha.substr(
                13,
                3
            )}-${((parseInt(slsha.substr(16, 2), 16) & 0x3f) | 0x80).toString(
                16
            )}${slsha.substr(18, 2)}-${slsha.substr(20, 12)}`;
        });
    }

    const nowz = getnowz(); 
    const etime = new Date(srq.getTime() + nowz * yzhm);

    const dnowUIDP = ceID(my + nowz);
    const 上一个UUIDPromise = ceID(my + (nowz - 1));

    const endtimeUTC = new Date(etime.getTime() - sqpy * 60 * 60 * 1000); 
    const endtimestr = `到期时间(UTC): ${endtimeUTC
        .toISOString()
        .slice(0, 19)
        .replace("T", " ")} (UTC+8): ${etime
            .toISOString()
            .slice(0, 19)
            .replace("T", " ")}\n`;

    return Promise.all([dnowUIDP, 上一个UUIDPromise, endtimestr]);
}

async function qydzlist(env, txt = "ADD.txt") {
    const osj = await env.KV.get(`/${txt}`);
    const nsj = await env.KV.get(txt);

    if (osj && !nsj) {
        await env.KV.put(txt, osj);
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function KV(request, env, txt = "ADD.txt") {
    try {
        if (request.method === "POST") {
            if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
            try {
                const content = await request.text();
                await env.KV.put(txt, content);
                return new Response("保存成功");
            } catch (error) {
                console.error("保存KV时发生错误:", error);
                return new Response("保存失败: " + error.message, { status: 500 });
            }
        }

        let content = "";
        let hasKV = !!env.KV;

        if (hasKV) {
            try {
                content = (await env.KV.get(txt)) || "";
            } catch (error) {
                console.error("读取KV时发生错误:", error);
                content = "读取数据时发生错误: " + error.message;
            }
        }

        const html = `
			<!DOCTYPE html>
			<html>
			<head>
				<title>优选订阅列表</title>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<style>
					body {
						margin: 0;
						padding: 15px; /* 调整padding */
						box-sizing: border-box;
						font-size: 13px; /* 设置全局字体大小 */
					}
					.editor-container {
						width: 100%;
						max-width: 100%;
						margin: 0 auto;
					}
					.editor {
						width: 100%;
						height: 520px; /* 调整高度 */
						margin: 15px 0; /* 调整margin */
						padding: 10px; /* 调整padding */
						box-sizing: border-box;
						border: 1px solid #ccc;
						border-radius: 4px;
						font-size: 13px;
						line-height: 1.5;
						overflow-y: auto;
						resize: none;
					}
					.save-container {
						margin-top: 8px; /* 调整margin */
						display: flex;
						align-items: center;
						gap: 10px; /* 调整gap */
					}
					.save-btn, .back-btn {
						padding: 6px 15px; /* 调整padding */
						color: white;
						border: none;
						border-radius: 4px;
						cursor: pointer;
					}
					.save-btn {
						background: #4CAF50;
					}
					.save-btn:hover {
						background: #45a049;
					}
					.back-btn {
						background: #666;
					}
					.back-btn:hover {
						background: #555;
					}
					.save-status {
						color: #666;
					}
					.notice-content {
						display: none;
						margin-top: 10px;
						font-size: 13px;
						color: #333;
					}
				</style>
			</head>
			<body>
				################################################################<br>
				${FileName} 优选订阅列表:<br>
				---------------------------------------------------------------<br>
				&nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">注意事项∨</a></strong><br>
				<div id="noticeContent" class="notice-content">
					${decodeURIComponent(
            atob(
                "JTA5JTA5JTA5JTA5JTA5JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBRERBUEklMjAlRTUlQTYlODIlRTYlOUUlOUMlRTYlOTglQUYlRTUlOEYlOEQlRTQlQkIlQTNJUCVFRiVCQyU4QyVFNSU4RiVBRiVFNCVCRCU5QyVFNCVCOCVCQVBST1hZSVAlRTclOUElODQlRTglQUYlOUQlRUYlQkMlOEMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwcm94eWlwJTNEdHJ1ZSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZyZWZzJTJGaGVhZHMlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZyZWZzJTJGaGVhZHMlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzQiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZyZWZzJTJGaGVhZHMlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QuY3N2JTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUzQ3N0cm9uZyUzRSUyNiUzQyUyRnN0cm9uZyUzRXBvcnQlM0QyMDUzJTNDYnIlM0U="
            )
        )}
				</div>
				<div class="editor-container">
					${hasKV
                ? `
					<textarea class="editor" 
						placeholder="${decodeURIComponent(
                    atob(
                        "QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=="
                    )
                )}"
						id="content">${content}</textarea>
					<div class="save-container">
						<button class="back-btn" onclick="goBack()">返回配置页</button>
						<button class="save-btn" onclick="saveContent(this)">保存</button>
						<span class="save-status" id="saveStatus"></span>
					</div>
					<br>
					################################################################<br>
					${cmad}
					`
                : "<p>未绑定KV空间</p>"
            }
				</div>
		
				<script>
				if (document.querySelector('.editor')) {
					let timer;
					const textarea = document.getElementById('content');
					const originalContent = textarea.value;
		
					function goBack() {
						const currentUrl = window.location.href;
						const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
						window.location.href = parentUrl;
					}
		
					function replaceFullwidthColon() {
						const text = textarea.value;
						textarea.value = text.replace(/：/g, ':');
					}
					
					function saveContent(button) {
						try {
							const updateButtonText = (step) => {
								button.textContent = \`保存中: \${step}\`;
							};
							// 检测是否为iOS设备
							const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
							
							// 仅在非iOS设备上执行replaceFullwidthColon
							if (!isIOS) {
								replaceFullwidthColon();
							}
							updateButtonText('开始保存');
							button.disabled = true;
							// 获取textarea内容和原始内容
							const textarea = document.getElementById('content');
							if (!textarea) {
								throw new Error('找不到文本编辑区域');
							}
							updateButtonText('获取内容');
							let newContent;
							let originalContent;
							try {
								newContent = textarea.value || '';
								originalContent = textarea.defaultValue || '';
							} catch (e) {
								console.error('获取内容错误:', e);
								throw new Error('无法获取编辑内容');
							}
							updateButtonText('准备状态更新函数');
							const updateStatus = (message, isError = false) => {
								const statusElem = document.getElementById('saveStatus');
								if (statusElem) {
									statusElem.textContent = message;
									statusElem.style.color = isError ? 'red' : '#666';
								}
							};
							updateButtonText('准备按钮重置函数');
							const resetButton = () => {
								button.textContent = '保存';
								button.disabled = false;
							};
							if (newContent !== originalContent) {
								updateButtonText('发送保存请求');
								fetch(window.location.href, {
									method: 'POST',
									body: newContent,
									headers: {
										'Content-Type': 'text/plain;charset=UTF-8'
									},
									cache: 'no-cache'
								})
								.then(response => {
									updateButtonText('检查响应状态');
									if (!response.ok) {
										throw new Error(\`HTTP error! status: \${response.status}\`);
									}
									updateButtonText('更新保存状态');
									const now = new Date().toLocaleString();
									document.title = \`编辑已保存 \${now}\`;
									updateStatus(\`已保存 \${now}\`);
								})
								.catch(error => {
									updateButtonText('处理错误');
									console.error('Save error:', error);
									updateStatus(\`保存失败: \${error.message}\`, true);
								})
								.finally(() => {
									resetButton();
								});
							} else {
								updateButtonText('检查内容变化');
								updateStatus('内容未变化');
								resetButton();
							}
						} catch (error) {
							console.error('保存过程出错:', error);
							button.textContent = '保存';
							button.disabled = false;
							const statusElem = document.getElementById('saveStatus');
							if (statusElem) {
								statusElem.textContent = \`错误: \${error.message}\`;
								statusElem.style.color = 'red';
							}
						}
					}
		
					textarea.addEventListener('blur', saveContent);
					textarea.addEventListener('input', () => {
						clearTimeout(timer);
						timer = setTimeout(saveContent, 5000);
					});
				}
		
				function toggleNotice() {
					const noticeContent = document.getElementById('noticeContent');
					const noticeToggle = document.getElementById('noticeToggle');
					if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
						noticeContent.style.display = 'block';
						noticeToggle.textContent = '注意事项∧';
					} else {
						noticeContent.style.display = 'none';
						noticeToggle.textContent = '注意事项∨';
					}
				}
		
				// 初始化 noticeContent 的 display 属性
				document.addEventListener('DOMContentLoaded', () => {
					document.getElementById('noticeContent').style.display = 'none';
				});
				</script>
			</body>
			</html>
		`;

        return new Response(html, {
            headers: { "Content-Type": "text/html;charset=utf-8" },
        });
    } catch (error) {
        console.error("处理请求时发生错误:", error);
        return new Response("服务器错误: " + error.message, {
            status: 500,
            headers: { "Content-Type": "text/plain;charset=utf-8" },
        });
    }
}