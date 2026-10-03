// 生成“本题捕获样例”：
//  - good.pcap.b64     ：乱序 + IP 分片（乱序到达）+ 回绕 + 相同字节重传，应重建出 4 条指令
//  - conflict.pcap.b64 ：同序号重传但字节被篡改，必须 CONFLICT 拒绝
//  - manifest.json     ：期望结论，供 verify 冒烟比对
import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { arpFrame, makeSession, pcap } from '../verify/builder.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '..', 'public', 'samples');

const TUPLE = { srcIp: '10.20.30.40', dstIp: '10.20.30.99', srcPort: 5001, dstPort: 9100 };
const COMMANDS = ['NAV FIX A1', 'THR 87 PCT', 'HOLD LEVEL', 'CHK 0x4F2A'];
const ISN = 0xffffffe0;

function buildGood() {
  const s = makeSession({
    srcIpS: TUPLE.srcIp, dstIpS: TUPLE.dstIp,
    sport: TUPLE.srcPort, dport: TUPLE.dstPort,
    isn: ISN, id: 0x3300, commands: COMMANDS,
  });
  const frames = [];
  frames.push(arpFrame());                       // #1 无关噪声
  frames.push(s.syn());                          // #2 SYN（ISN）
  frames.push(s.synack());                       // #3 反向 SYN/ACK
  const frags = s.dataFrags(0, 16, 8);           // 流 [0,16) 切成 5 个 IP 分片
  for (const i of [2, 0, 4, 1, 3]) frames.push(frags[i]); // #4..#8 分片乱序到达
  frames.push(s.data(16, 16));                   // #9 流 [16,32)，越过 0xFFFFFFFF 回绕
  frames.push(s.data(8, 8));                     // #10 同字节重传 [8,16)
  frames.push(s.data(32, 16));                   // #11 回绕后 [32,48)
  frames.push(s.data(24, 16));                   // #12 同字节重传 [24,40)，跨两段
  frames.push(s.fin(48));                        // #13 FIN
  frames.push(s.serverFin());                    // #14 反向 FIN
  return pcap(frames);
}

function buildConflict() {
  const s = makeSession({
    srcIpS: TUPLE.srcIp, dstIpS: TUPLE.dstIp,
    sport: TUPLE.srcPort, dport: TUPLE.dstPort,
    isn: ISN, id: 0x4400, commands: COMMANDS,
  });
  const tampered = Buffer.from(s.stream.subarray(24, 40));
  tampered[6] ^= 0xff; // 流内绝对偏移 30 的字节被改
  const frames = [];
  frames.push(arpFrame());                       // #1
  frames.push(s.syn());                          // #2
  frames.push(s.synack());                       // #3
  const frags = s.dataFrags(0, 16, 8);
  for (const i of [2, 0, 4, 1, 3]) frames.push(frags[i]); // #4..#8
  frames.push(s.data(16, 16));                   // #9 持有原始偏移 30
  frames.push(s.data(8, 8));                     // #10 正常重传
  frames.push(s.data(32, 16));                   // #11
  frames.push(s.data(24, 16, { data: tampered }));// #12 同序号、字节冲突
  frames.push(s.fin(48));                        // #13
  frames.push(s.serverFin());                    // #14
  return pcap(frames);
}

const good = buildGood();
const conflict = buildConflict();
await mkdir(OUT, { recursive: true });
await writeFile(path.join(OUT, 'good.pcap.b64'), good.toString('base64') + '\n');
await writeFile(path.join(OUT, 'conflict.pcap.b64'), conflict.toString('base64') + '\n');

// good 样例的逐包归因期望（手工推算，与生成代码相互独立，供 verify 冒烟复算比对）：
// 流内承载：#4=frag2→[0,4)  #8=frag3→[4,12)  #6=frag4→[12,16)  #9→[16,32)  #11→[32,48)
// 重传叠加：#10→[8,16)  #12→[24,40)；4 条指令各占 12 字节（2 前缀 + 10 载荷）。
const GOOD_ATTRIBUTION = [
  { byteRange: [0, 12], packets: [4, 8, 10], packetRanges: [
    { packet: 4, byteRange: [0, 4] },
    { packet: 8, byteRange: [4, 12] },
    { packet: 10, byteRange: [8, 12] },
  ] },
  { byteRange: [12, 24], packets: [6, 9, 10], packetRanges: [
    { packet: 6, byteRange: [12, 16] },
    { packet: 9, byteRange: [16, 24] },
    { packet: 10, byteRange: [12, 16] },
  ] },
  { byteRange: [24, 36], packets: [9, 11, 12], packetRanges: [
    { packet: 9, byteRange: [24, 32] },
    { packet: 11, byteRange: [32, 36] },
    { packet: 12, byteRange: [24, 36] },
  ] },
  { byteRange: [36, 48], packets: [11, 12], packetRanges: [
    { packet: 11, byteRange: [36, 48] },
    { packet: 12, byteRange: [36, 40] },
  ] },
];

const manifest = {
  tuple: TUPLE,
  isn: ISN >>> 0,
  good: {
    file: 'good.pcap.b64',
    packetCount: 14,
    synPacket: 2,
    finPacket: 13,
    streamLength: COMMANDS.reduce((n, c) => n + 2 + c.length, 0),
    commands: COMMANDS.map((text, i) => ({ index: i, text, ...GOOD_ATTRIBUTION[i] })),
  },
  conflict: {
    file: 'conflict.pcap.b64',
    code: 'CONFLICT',
    packet: 9,
    packet2: 12,
    offset: 30,
    range: [30, 31],
  },
};
await writeFile(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`samples written to ${OUT}`);
