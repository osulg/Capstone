import { useState } from "react";

import type { Bucket } from "../eventStats";

// 시간별 이벤트 수 꺾은선 그래프 (SVG, 외부 라이브러리 없음)
// 그래프에는 선과 HIGH 점만 그리고, 설명은 빨간 점에 마우스를 올렸을 때만 띄운다.
const W = 1000, H = 320;
const X0 = 44, X1 = 984, Y0 = 286, Y1 = 18;
const FONT = "inherit";

export default function EventChart({ data }: { data: Bucket[] }) {
  const [hover, setHover] = useState<number | null>(null);

  if (data.length === 0) {
    return <div className="chart"><div className="empty" style={{ height: H - 20, border: 0 }}>표시할 이벤트가 없습니다.</div></div>;
  }

    // 눈금 5개(0, 1/4 … 1)가 모두 정수가 되도록 최댓값을 4의 배수로 올린다
  const top = Math.max(4, Math.ceil(Math.max(...data.map((b) => b.count)) / 4) * 4);
  const x = (i: number) => (data.length === 1 ? (X0 + X1) / 2 : X0 + ((X1 - X0) * i) / (data.length - 1));
  const y = (v: number) => Y0 - ((Y0 - Y1) * v) / top;
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((r) => Math.round(top * r));
  const labelEvery = Math.max(1, Math.ceil(data.length / 7));

  const line = data.map((b, i) => `${i ? "L" : "M"}${x(i)},${y(b.count)}`).join(" ");
  const highs = data.map((b, i) => ({ b, i })).filter(({ b }) => b.highs.length > 0);

  const tip = hover !== null ? data[hover] : null;
  const tipLeft = hover !== null ? (x(hover) / W) * 100 : 0;

  return (
    <div className="chart chart-v2">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} role="img"
        aria-label="시간별 보안 위협 이벤트 수 꺾은선 그래프">

        {/* 가로 눈금선과 y값 */}
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={X0} y1={y(v)} x2={X1} y2={y(v)} stroke={v === 0 ? "#bdbdbd" : "#ececec"} strokeWidth="1" />
            <text x={X0 - 10} y={y(v) + 4} textAnchor="end" fontSize="11" fill="#8a8a8a" fontFamily={FONT}>{v}</text>
          </g>
        ))}

        {/* x축 시간 */}
        {data.map((b, i) => (i % labelEvery === 0 || i === data.length - 1) && (
          <text key={i} x={x(i)} y={H - 10} textAnchor={i === data.length - 1 ? "end" : i === 0 ? "start" : "middle"}
            fontSize="11" fill="#8a8a8a" fontFamily={FONT}>{b.label}</text>
        ))}

        {/* 선 */}
        <path d={line} fill="none" stroke="#111" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />

        {/* 마우스를 올린 HIGH 점의 세로 안내선 */}
        {hover !== null && (
          <line x1={x(hover)} y1={Y1} x2={x(hover)} y2={Y0} stroke="#c00000" strokeWidth="1" strokeDasharray="3 3" />
        )}

        {/* HIGH 점: 보이는 점은 작게, 마우스가 닿는 영역은 넓게 */}
        {highs.map(({ b, i }) => (
          <g key={i} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} style={{ cursor: "pointer" }}>
            <circle cx={x(i)} cy={y(b.count)} r="14" fill="transparent" />
            <circle cx={x(i)} cy={y(b.count)} r={hover === i ? 6.5 : 5} fill="#c00000" stroke="#fff" strokeWidth="2" />
          </g>
        ))}
      </svg>

      {tip && (
        <div className="chart-tip" style={{ left: `${tipLeft}%`, top: `${(y(tip.count) / H) * 100}%` }}
          data-side={tipLeft > 60 ? "left" : "right"} data-v={y(tip.count) < H * 0.45 ? "below" : "middle"}>
          <div className="chart-tip-head">{tip.label} · 이벤트 {tip.count}건</div>
          {tip.highs.map((h) => (
            <div key={h.pid} className="chart-tip-row">
              <b>HIGH</b> {h.process} (PID {h.pid})
              <span>{h.reason}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
