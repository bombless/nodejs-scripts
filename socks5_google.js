const net = require('net');
const tls = require('tls');

// ==============================================================================
// 配置项
// ==============================================================================
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 7897;
const TARGET_HOST = 'www.google.com';
const TARGET_PORT = 443; // HTTPS 端口

// ==============================================================================
// 辅助工具函数：将二进制 Buffer 格式化为美观的十六进制和 ASCII 显示
// ==============================================================================
function dumpBuffer(buffer, label) {
  console.log(`\n------------------------------------------------------------`);
  console.log(`【${label}】 (总长度: ${buffer.length} 字节)`);
  console.log(`十六进制: ${buffer.toString('hex').match(/.{1,2}/g).join(' ')}`);
  
  // 逐字节解析列表
  const bytesHex = [];
  const bytesDec = [];
  for (let i = 0; i < buffer.length; i++) {
    bytesHex.push('0x' + buffer[i].toString(16).padStart(2, '0'));
    bytesDec.push(buffer[i].toString().padStart(4, ' '));
  }
  console.log(`字节数值(Hex): [ ${bytesHex.join(', ')} ]`);
  console.log(`字节数值(Dec): [ ${bytesDec.join(', ')} ]`);
  console.log(`------------------------------------------------------------`);
}

// ==============================================================================
// 状态机与处理流程
// ==============================================================================
// 步骤说明：
//   STEP 0: 建立与 SOCKS5 代理的 TCP 握手
//   STEP 1: SOCKS5 握手认证协商 (Greeting / Method Selection)
//   STEP 2: 发送 SOCKS5 CONNECT 请求
//   STEP 3: 升级为 TLS 握手 (因为访问的是 HTTPS 443 端口)
//   STEP 4: 发送 HTTP 请求并读取回复
// ==============================================================================

let currentStep = 'GREETING';

console.log(`[步骤 1] 正在创建原生 TCP 套接字，连接本机的 SOCKS5 代理: ${PROXY_HOST}:${PROXY_PORT} ...`);
const socket = net.createConnection({ host: PROXY_HOST, port: PROXY_PORT }, () => {
  console.log(`✓ 成功建立与 SOCKS5 代理服务器的 TCP 连接！\n`);

  // ============================================================================
  // [步骤 2] 发送 SOCKS5 认证协商请求 (RFC 1928 - Method Selection)
  //
  // 协议规定客户端发送的数据格式：
  // +----+----------+----------+
  // |VER | NMETHODS | METHODS  |
  // +----+----------+----------+
  // | 1  |    1     | 1 to 255 |
  // +----+----------+----------+
  // 字段说明：
  // 1. VER (1 字节): SOCKS 协议版本号，固定为 0x05。
  // 2. NMETHODS (1 字节): 客户端支持的认证方法数量。我们只支持 1 种，所以是 0x01。
  // 3. METHODS (N 字节): 支持的认证方法列表。
  //    - 0x00: 无需认证 (NO AUTHENTICATION REQUIRED)
  //    - 0x01: GSSAPI
  //    - 0x02: 用户名/密码认证 (USERNAME/PASSWORD)
  //    - 0x03 ~ 0x7F: IANA 分配
  //    - 0x80 ~ 0xFE: 私有方法保留
  //    - 0xFF: 无可接受的方法
  // ============================================================================
  const greetingReq = Buffer.from([
    0x05, // SOCKS 协议版本: 5
    0x01, // 支持的认证方法数: 1 种
    0x00  // 认证方法编号: 0x00 (无需认证)
  ]);

  dumpBuffer(greetingReq, '发送 -> SOCKS5 协商认证请求 (Greeting)');
  console.log('  字段解释:');
  console.log('    [0x05] VER      : SOCKS 版本 5');
  console.log('    [0x01] NMETHODS : 支持 1 种认证方法');
  console.log('    [0x00] METHODS  : 方法为 0x00 (无需认证)');

  socket.write(greetingReq);
});

// 监听从 SOCKS5 代理服务器发回的原生 TCP 数据
socket.on('data', (data) => {
  if (currentStep === 'GREETING') {
    // ==========================================================================
    // [步骤 2 响应] 接收 SOCKS5 认证协商回复
    //
    // 代理服务端回复的数据格式：
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    // 字段说明：
    // 1. VER (1 字节): SOCKS 协议版本 (应为 0x05)。
    // 2. METHOD (1 字节): 服务端选中的认证方法。
    //    - 0x00: 接受无需认证，握手成功。
    //    - 0xFF: 协商失败，没有客户端与服务端同时支持的认证方法。
    // ==========================================================================
    dumpBuffer(data, '接收 <- SOCKS5 协商认证回复');
    console.log('  字段解释:');
    console.log(`    [0x${data[0].toString(16).padStart(2, '0')}] VER    : 代理返回的 SOCKS 版本`);
    console.log(`    [0x${data[1].toString(16).padStart(2, '0')}] METHOD : 代理选定的认证方式 (0x00 代表无需认证)`);

    if (data[0] !== 0x05 || data[1] !== 0x00) {
      console.error('✗ SOCKS5 协商失败，代理拒绝或需要密码认证！');
      socket.destroy();
      return;
    }
    console.log('✓ SOCKS5 认证协商成功！\n');

    // ==========================================================================
    // [步骤 3] 发送 SOCKS5 CONNECT 请求
    //
    // 协议规定客户端发送的数据格式：
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // 字段说明：
    // 1. VER (1 字节): 0x05 (SOCKS5 版本)
    // 2. CMD (1 字节): 命令类型
    //    - 0x01: CONNECT (要求代理代为建立到目标主机的 TCP 隧道)
    //    - 0x02: BIND (用于 FTP 等需要反向建立连接的协议)
    //    - 0x03: UDP ASSOCIATE (用于 UDP 代理转发)
    // 3. RSV (1 字节): 保留字节，固定为 0x00
    // 4. ATYP (1 字节): 目标地址类型
    //    - 0x01: IPv4 地址 (长度固定为 4 字节)
    //    - 0x03: 域名 (第 1 字节表示域名长度 N，后续跟 N 字节的 ASCII 域名)
    //    - 0x04: IPv6 地址 (长度固定为 16 字节)
    // 5. DST.ADDR: 目标地址。以域名 www.google.com 为例，先是 1 字节长度 (14 = 0x0e)，随后是 14 字节域名字符。
    // 6. DST.PORT (2 字节): 网络字节序（大端序 Big-Endian）的目标端口号。
    //    - 443 的十六进制是 0x01BB (高位字节 0x01, 低位字节 0xBB)。
    // ==========================================================================
    const domainBuffer = Buffer.from(TARGET_HOST, 'ascii');
    const portBuffer = Buffer.alloc(2);
    portBuffer.writeUInt16BE(TARGET_PORT, 0); // 443 -> 0x01bb

    const connectReq = Buffer.concat([
      Buffer.from([
        0x05,                // VER: 0x05
        0x01,                // CMD: 0x01 (CONNECT)
        0x00,                // RSV: 0x00 (保留位)
        0x03,                // ATYP: 0x03 (域名类型)
        domainBuffer.length  // 域名的字节长度
      ]),
      domainBuffer,          // 目标域名字节 (ASCII: www.google.com)
      portBuffer             // 目标端口 (大端序: 0x01 0xbb)
    ]);

    currentStep = 'CONNECT';
    dumpBuffer(connectReq, '发送 -> SOCKS5 CONNECT 请求');
    console.log('  字段解释:');
    console.log('    [0x05] VER      : SOCKS 版本 5');
    console.log('    [0x01] CMD      : 0x01 代表 CONNECT 请求');
    console.log('    [0x00] RSV      : 保留位，固定为 0x00');
    console.log('    [0x03] ATYP     : 地址类型为 0x03 (域名)');
    console.log(`    [0x${domainBuffer.length.toString(16).padStart(2, '0')}] LEN      : 域名长度为 ${domainBuffer.length} 字节`);
    console.log(`    [ASCII] DOMAIN  : "${TARGET_HOST}"`);
    console.log(`    [0x${portBuffer[0].toString(16).padStart(2, '0')} 0x${portBuffer[1].toString(16).padStart(2, '0')}] PORT : 目标端口 ${TARGET_PORT} (大端序 16 位整数)`);

    socket.write(connectReq);

  } else if (currentStep === 'CONNECT') {
    // ==========================================================================
    // [步骤 3 响应] 接收 SOCKS5 CONNECT 回复
    //
    // 代理服务端回复的数据格式：
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // 字段说明：
    // 1. VER (1 字节): SOCKS 版本 0x05
    // 2. REP (1 字节): 应答状态码
    //    - 0x00: 成功 (succeeded)
    //    - 0x01: 一般性 SOCKS 服务器故障 (general failure)
    //    - 0x02: 规则集不允许该连接 (connection not allowed)
    //    - 0x03: 网络不可达 (network unreachable)
    //    - 0x04: 主机不可达 (host unreachable)
    //    - 0x05: 连接被拒绝 (connection refused)
    //    - 0x06: TTL 过期 (TTL expired)
    //    - 0x07: 命令不支持 (command not supported)
    //    - 0x08: 地址类型不支持 (address type not supported)
    // 3. RSV (1 字节): 保留字节，固定为 0x00
    // 4. ATYP (1 字节): 绑定的地址类型 (0x01 IPv4 / 0x03 域名 / 0x04 IPv6)
    // 5. BND.ADDR: 代理服务器为此次连接分配/绑定的 IP 地址
    // 6. BND.PORT: 代理服务器分配/绑定的端口号 (2 字节大端序)
    // ==========================================================================
    dumpBuffer(data, '接收 <- SOCKS5 CONNECT 回复');

    const rep = data[1];
    const repDesc = {
      0x00: '0x00 成功 (succeeded)',
      0x01: '0x01 一般性服务器故障',
      0x02: '0x02 规则不允许连接',
      0x03: '0x03 网络不可达',
      0x04: '0x04 主机不可达',
      0x05: '0x05 连接被拒绝',
      0x06: '0x06 TTL 过期',
      0x07: '0x07 命令不支持',
      0x08: '0x08 地址类型不支持'
    }[rep] || `0x${rep.toString(16)} 未知错误`;

    console.log('  字段解释:');
    console.log(`    [0x${data[0].toString(16).padStart(2, '0')}] VER      : SOCKS 版本`);
    console.log(`    [0x${data[1].toString(16).padStart(2, '0')}] REP      : ${repDesc}`);
    console.log(`    [0x${data[2].toString(16).padStart(2, '0')}] RSV      : 保留位`);
    console.log(`    [0x${data[3].toString(16).padStart(2, '0')}] ATYP     : 绑定的地址类型`);

    if (rep !== 0x00) {
      console.error(`✗ SOCKS5 CONNECT 失败，错误原因: ${repDesc}`);
      socket.destroy();
      return;
    }

    console.log('\n============================================================');
    console.log('🎉 恭喜！SOCKS5 隧道建立成功！');
    console.log('此时该 TCP 连接已直通目标主机 https://www.google.com:443');
    console.log('接下来在该 TCP 连接上运行 TLS 协议握手与 HTTPS 请求...');
    console.log('============================================================\n');

    // 移除原有 raw TCP socket 的 data 事件监听器，交给 TLS 引擎接管
    socket.removeAllListeners('data');
    currentStep = 'TUNNEL_ESTABLISHED';

    // ==========================================================================
    // [步骤 4] 将原套接字包装为 TLS 加密套接字 (TLS Handshake)
    //
    // 说明：
    //   443 端口是 HTTPS 服务，如果直接发送明文的 "GET / HTTP/1.1\r\n..."，
    //   目标服务器会认为数据非法（因为服务器期望先进行 TLS Client Hello 握手）。
    //   使用 Node.js 的 `tls.connect` 并传入已打通的 `socket` 参数，
    //   可以在原有套接字上原地升级，完成 TLS 握手、证书验证及密钥协商。
    // ==========================================================================
    console.log('[步骤 4] 正在对 TCP 隧道进行 TLS/SSL 包装并开始 TLS 握手...');

    const tlsSocket = tls.connect({
      socket: socket,             // 复用已经连通的 SOCKS5 隧道套接字
      servername: TARGET_HOST,    // 启用 SNI (Server Name Indication)，Google 会以此返回对应域名的证书
      rejectUnauthorized: true    // 严格校验 SSL 证书合法性
    }, () => {
      console.log('✓ TLS 握手成功！安全通道已建立。');
      console.log(`  使用的加密套件: ${tlsSocket.getCipher().name} (${tlsSocket.getProtocol()})`);

      // ========================================================================
      // [步骤 5] 在 TLS 加密信道中发送标准 HTTP/1.1 GET 请求
      //
      // HTTP 文本协议请求格式：
      // 请求行: METHOD /path HTTP/1.1\r\n
      // 请求头: Header-Name: Header-Value\r\n
      // 空行:   \r\n (表示请求头结束)
      // ========================================================================
      const httpRequest = [
        `GET / HTTP/1.1`,
        `Host: ${TARGET_HOST}`,
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NodeSocks5Demo/1.0`,
        `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
        `Accept-Language: zh-CN,zh;q=0.9,en;q=0.8`,
        `Connection: close`, // 请求完成后让服务端关闭连接，方便我们接收完整响应
        ``,
        ``
      ].join('\r\n');

      console.log(`\n[步骤 5] 正在发送 HTTP 请求：`);
      console.log('------------------ [HTTP 请求报文明文] ------------------');
      console.log(httpRequest.trimEnd());
      console.log('---------------------------------------------------------');

      tlsSocket.write(httpRequest);
    });

    // 存储累积接收到的响应数据
    const responseChunks = [];

    // 接收解密后的 HTTP 响应数据
    tlsSocket.on('data', (chunk) => {
      responseChunks.push(chunk);
    });

    // 响应接收完毕
    tlsSocket.on('end', () => {
      const fullResponse = Buffer.concat(responseChunks).toString('utf8');
      
      console.log('\n[步骤 6] 收到 Google 完整的 HTTP 响应数据：');
      console.log('================== [HTTP 响应报文分析] ==================');
      
      // 分离 HTTP 响应头与响应体 (通过 \r\n\r\n 分割)
      const headerEndIndex = fullResponse.indexOf('\r\n\r\n');
      if (headerEndIndex !== -1) {
        const headerPart = fullResponse.slice(0, headerEndIndex);
        const bodyPart = fullResponse.slice(headerEndIndex + 4);

        console.log('【1. 响应状态行与响应头 (Headers)】:');
        console.log(headerPart);
        console.log('\n【2. 响应正文 (Body 预览，前 500 字符)】:');
        console.log(bodyPart.slice(0, 500));
        console.log(`\n... (正文总长度: ${Buffer.byteLength(bodyPart, 'utf8')} 字节)`);
      } else {
        console.log(fullResponse.slice(0, 1000));
      }
      console.log('=========================================================\n');
      console.log('✨ 流程全部执行完毕！');
    });

    tlsSocket.on('error', (err) => {
      console.error('✗ TLS 过程发生错误:', err.message);
    });
  }
});

socket.on('error', (err) => {
  console.error('✗ TCP 连接发生错误:', err.message);
});

socket.on('close', () => {
  console.log('[通知] 原始底层 TCP 连接已关闭。');
});
