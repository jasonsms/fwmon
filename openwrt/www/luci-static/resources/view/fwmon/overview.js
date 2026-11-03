'use strict';
'require view';
'require fs';

function fmt(n) { return Number(n || 0).toLocaleString(); }

function parse(raw) {
	try { return JSON.parse(raw); } catch (e) { return {}; }
}

return view.extend({
	load: function () {
		return L.resolveDefault(fs.read('/tmp/fwmon/panel.json'), '{}');
	},

	render: function (raw) {
		var p = parse(raw);
		var s = p.summary || {};
		var h = p.health || {};
		var hourly = (s.hourly && s.hourly.new_total) || [];

		var metrics = [
			['今日新建入站', fmt(s.events)],
			['独立源 IP', fmt(s.unique_ips)],
			['放行命中', fmt(s.accept)],
			['已丢弃', fmt(s.drop)],
			['追踪源数', fmt(h.tracked_ips)],
			['放行端口', String(h.exposed_port || '-')]
		];

		var cards = metrics.map(function (m) {
			return E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, m[0]),
				E('div', { 'class': 'cbi-value-field' }, [E('strong', m[1])])
			]);
		});

		var max = Math.max.apply(null, hourly.concat([1]));
		var bars = hourly.map(function (v, i) {
			return E('div', {
				'style': 'display:inline-block;width:3.4%;height:' +
					Math.max(2, Math.round((v / max) * 80)) +
					'px;background:#378add;vertical-align:bottom;margin:0 0.3%;',
				'title': i + ':00 — ' + v
			});
		});

		var status = E('p', { 'class': 'cbi-section-descr' },
			(h.conntrack_alive ? 'conntrack 采集中。' : 'conntrack 未运行（检查 conntrack-tools）。') +
			' 日期：' + (h.date || '-') + '；数据与 fn-knock（L7）互补，仅记入站新建连接。');

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, '入站监控 · 概览'),
			E('div', { 'class': 'cbi-section' }, cards),
			E('h3', {}, '每小时新建入站'),
			E('div', { 'style': 'height:92px;white-space:nowrap;padding:4px 0;' }, bars),
			status
		]);
	}
});
