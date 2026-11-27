import type { AdminOverviewTrendDay } from './contract'

const WIDTH = 640
const HEIGHT = 220
const TOP = 14
const BOTTOM = 26
const SIDE = 10

/** User trend chart: bars are new users per day, the line is active users. Pure SVG, no chart library. */
export function OverviewTrendChart({
  days,
  newUsersLabel,
  activeUsersLabel,
}: {
  days: readonly AdminOverviewTrendDay[]
  newUsersLabel: string
  activeUsersLabel: string
}) {
  const chartHeight = HEIGHT - TOP - BOTTOM
  const baseline = TOP + chartHeight
  const max = Math.max(1, ...days.flatMap((day) => [day.new_users, day.active_users]))
  const slot = days.length === 0 ? 0 : (WIDTH - SIDE * 2) / days.length
  const barWidth = Math.min(24, slot * 0.5)
  const x = (index: number): number => SIDE + slot * index + slot / 2
  const y = (value: number): number => baseline - (value / max) * chartHeight

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-4 text-[12px] text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-[3px] bg-[#0832AA]" aria-hidden="true" />
          {newUsersLabel}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-[2px] w-4 rounded-full bg-[#15966a]" aria-hidden="true" />
          {activeUsersLabel}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="h-auto w-full text-muted-foreground"
        role="img"
        aria-label={`${newUsersLabel}, ${activeUsersLabel}`}
      >
        <line x1={SIDE} y1={baseline} x2={WIDTH - SIDE} y2={baseline} stroke="currentColor" strokeOpacity="0.25" strokeWidth="1" />
        {days.map((day, index) => {
          const barHeight = (day.new_users / max) * chartHeight
          return (
            <g key={day.date}>
              <rect
                x={x(index) - barWidth / 2}
                y={baseline - barHeight}
                width={barWidth}
                height={Math.max(0, barHeight)}
                rx="3"
                fill="#0832AA"
                fillOpacity="0.85"
              >
                <title>{`${day.date}: ${newUsersLabel} ${day.new_users}, ${activeUsersLabel} ${day.active_users}`}</title>
              </rect>
              <text x={x(index)} y={HEIGHT - 8} textAnchor="middle" fontSize="10" fill="currentColor">
                {day.date.slice(5)}
              </text>
            </g>
          )
        })}
        {days.length > 1 ? (
          <polyline
            points={days.map((day, index) => `${x(index)},${y(day.active_users)}`).join(' ')}
            fill="none"
            stroke="#15966a"
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
        ) : null}
        {days.map((day, index) => (
          <circle key={day.date} cx={x(index)} cy={y(day.active_users)} r="3" fill="#15966a">
            <title>{`${day.date}: ${newUsersLabel} ${day.new_users}, ${activeUsersLabel} ${day.active_users}`}</title>
          </circle>
        ))}
      </svg>
    </div>
  )
}
