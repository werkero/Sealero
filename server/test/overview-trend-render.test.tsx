import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { OverviewTrendChart } from '../../src/features/admin/OverviewTrendChart';

const days = [
  { date: '2026-11-21', new_users: 0, active_users: 1 },
  { date: '2026-11-22', new_users: 1, active_users: 1 },
  { date: '2026-11-23', new_users: 2, active_users: 1 },
];

describe('OverviewTrendChart', () => {
  it('renders one bar per day, the active-user line, the legend and the day labels', () => {
    const html = renderToStaticMarkup(
      <OverviewTrendChart days={days} newUsersLabel="New users" activeUsersLabel="Active users" />,
    );
    expect(html).toContain('<svg');
    expect(html).toContain('New users');
    expect(html).toContain('Active users');
    expect(html.match(/<rect/g)?.length).toBe(3);
    expect(html).toContain('<polyline');
    expect(html.match(/<circle/g)?.length).toBe(3);
    expect(html).toContain('>11-21<');
    expect(html).toContain('>11-22<');
    expect(html).toContain('>11-23<');
  });

  it('renders an empty chart without crashing', () => {
    const html = renderToStaticMarkup(
      <OverviewTrendChart days={[]} newUsersLabel="New users" activeUsersLabel="Active users" />,
    );
    expect(html).toContain('<svg');
    expect(html).not.toContain('<rect');
    expect(html).not.toContain('<polyline');
  });
});
