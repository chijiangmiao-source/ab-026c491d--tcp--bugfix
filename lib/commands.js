import { fail } from './errors.js';

// 列出一条指令 [start,end) 内“每个实际承载其字节的原始包号—流内半开区间”。
// origins[i] 是承载流内第 i 字节的全部原始包号（完整/部分重叠的相同重传、
// 乱序段、IP 分片承载都会各自保留）。同一包号在指令内可能出现多个不相邻区间，
// 逐包号合并相邻字节，得到可独立复算的半开区间序列。
function packetRangesFor(origins, start, end) {
  const runsByPacket = new Map(); // packet -> Array<[lo, hi)>
  for (let pos = start; pos < end; pos++) {
    for (const packet of origins[pos]) {
      let runs = runsByPacket.get(packet);
      if (!runs) {
        runs = [];
        runsByPacket.set(packet, runs);
      }
      const last = runs[runs.length - 1];
      if (last && last[1] === pos) last[1] = pos + 1;
      else runs.push([pos, pos + 1]);
    }
  }
  const packets = [...runsByPacket.keys()].sort((a, b) => a - b);
  const ranges = [];
  for (const packet of packets) {
    for (const [lo, hi] of runsByPacket.get(packet)) {
      ranges.push({ packet, byteRange: [lo, hi] });
    }
  }
  return { packets, ranges };
}

// 长度前缀 ASCII 指令解析。
// 帧格式：[2 字节大端长度 n][n 字节 ASCII 载荷]，帧首尾相接。
// 要求：
//  - n 必须恰好被剩余字节容纳（长度不完整即截断指令，拒绝）；
//  - 载荷全部为可见 ASCII（0x20-0x7E）；
//  - 整段流必须被指令恰好耗尽，任何尾随残字节（连一个长度前缀都凑不齐）也拒绝。
export function parseCommands(stream, origins) {
  const firstPacketAt = (i) => (Array.isArray(origins[i]) ? origins[i][0] : null) ?? null;
  const commands = [];
  let pos = 0;
  const total = stream.length;
  while (pos < total) {
    if (total - pos < 2) {
      throw fail('TRAILING_BYTES',
        `流尾残留 ${total - pos} 字节，凑不出 2 字节长度前缀，拒绝输出任何半截指令`, {
          offset: pos,
          range: [pos, total],
          packet: firstPacketAt(pos),
        });
    }
    const n = (stream[pos] << 8) | stream[pos + 1];
    const prefixStart = pos;
    const payloadStart = pos + 2;
    const payloadEnd = payloadStart + n;
    if (n === 0) {
      throw fail('INVALID_COMMAND', '长度前缀为 0：空指令不构成有效 ASCII 指令', {
        offset: prefixStart,
        range: [prefixStart, payloadStart],
        packet: firstPacketAt(prefixStart),
      });
    }
    if (payloadEnd > total) {
      throw fail('TRUNCATED_COMMAND',
        `偏移 ${prefixStart} 处长度前缀声明 ${n} 字节载荷，但 FIN 前流只剩 ${total - payloadStart} 字节，指令被截断`, {
          offset: prefixStart,
          range: [prefixStart, total],
          packet: firstPacketAt(prefixStart),
          extra: { declaredLength: n, remaining: total - payloadStart },
        });
    }
    let text = '';
    for (let i = payloadStart; i < payloadEnd; i++) {
      const b = stream[i];
      if (b < 0x20 || b > 0x7e) {
        throw fail('NON_ASCII',
          `第 ${commands.length + 1} 条指令载荷偏移 ${i} 处字节 0x${b.toString(16).padStart(2, '0')} 不是可见 ASCII，拒绝输出`, {
            offset: i,
            range: [i, i + 1],
            packet: firstPacketAt(i),
          });
      }
      text += String.fromCharCode(b);
    }
    // 含 2 字节长度前缀在内，收集全部承载包号及各自流内半开区间
    const { packets, ranges } = packetRangesFor(origins, prefixStart, payloadEnd);
    commands.push({
      index: commands.length,
      text,
      length: n,
      byteRange: [prefixStart, payloadEnd],      // 含 2 字节长度前缀（流内半开区间）
      payloadRange: [payloadStart, payloadEnd],  // ASCII 载荷区间
      packets,
      packetRanges: ranges,
    });
    pos = payloadEnd;
  }
  return commands;
}
