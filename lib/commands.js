import { fail } from './errors.js';

// 汇总 [start, end) 内每个原始包号实际承载的流内半开区间。
// carriers[pos] 是该字节的全部承载包号（相同字节的重传段/分片全部在列）；
// 同一包号承载的多个不相邻区间分别列出，连续位置合并为一个半开区间。
function packetRangesFor(carriers, origin, start, end) {
  const runsByPacket = new Map(); // packet -> [[起, 止), ...]（位置递增遍历，可就地合并）
  for (let pos = start; pos < end; pos++) {
    const list = (carriers && carriers[pos])
      ?? (origin && origin[pos] ? [origin[pos]] : []);
    for (const packet of list) {
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
  const packetRanges = [];
  for (const packet of packets) {
    for (const byteRange of runsByPacket.get(packet)) {
      packetRanges.push({ packet, byteRange });
    }
  }
  return { packets, packetRanges };
}

// 长度前缀 ASCII 指令解析。
// 帧格式：[2 字节大端长度 n][n 字节 ASCII 载荷]，帧首尾相接。
// 要求：
//  - n 必须恰好被剩余字节容纳（长度不完整即截断指令，拒绝）；
//  - 载荷全部为可见 ASCII（0x20-0x7E）；
//  - 整段流必须被指令恰好耗尽，任何尾随残字节（连一个长度前缀都凑不齐）也拒绝。
// 归因：packets/packetRanges 列出实际承载该指令字节的全部原始包号
// （含字节相同的重传段与重叠分片）及各自对应的流内半开区间。
export function parseCommands(stream, origin, carriers) {
  const commands = [];
  let pos = 0;
  const total = stream.length;
  while (pos < total) {
    if (total - pos < 2) {
      throw fail('TRAILING_BYTES',
        `流尾残留 ${total - pos} 字节，凑不出 2 字节长度前缀，拒绝输出任何半截指令`, {
          offset: pos,
          range: [pos, total],
          packet: origin[pos] ?? null,
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
        packet: origin[prefixStart] ?? null,
      });
    }
    if (payloadEnd > total) {
      throw fail('TRUNCATED_COMMAND',
        `偏移 ${prefixStart} 处长度前缀声明 ${n} 字节载荷，但 FIN 前流只剩 ${total - payloadStart} 字节，指令被截断`, {
          offset: prefixStart,
          range: [prefixStart, total],
          packet: origin[prefixStart] ?? null,
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
            packet: origin[i] ?? null,
          });
      }
      text += String.fromCharCode(b);
    }
    const { packets, packetRanges } = packetRangesFor(carriers, origin, prefixStart, payloadEnd);
    commands.push({
      index: commands.length,
      text,
      length: n,
      byteRange: [prefixStart, payloadEnd],      // 含 2 字节长度前缀（流内半开区间）
      payloadRange: [payloadStart, payloadEnd],  // ASCII 载荷区间
      packets,       // 承载该指令的全部原始包号（升序，重传包一个不落）
      packetRanges,  // 每个包号各自对应的流内半开区间（按包号升序、区间起点升序）
    });
    pos = payloadEnd;
  }
  return commands;
}
