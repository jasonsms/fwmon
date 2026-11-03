'use strict';
'require view';
'require fs';

function parse(raw) { try { return JSON.parse(raw); } catch (e) { return {}; } }

var SEV = { info: '#378add', warn: '#ba7517', high: '#a32d2d', critical: '#501313' };
var TYPE = {
	scan: '端口扫描', flood: '连接泛洪', bruteforce: '暴力连接',
	spike: '流量突增', drop_anomaly: '丢弃异常', repeat: '惯犯'
};

return view.extend({
	load: function () {
		return L.resolveDefault(fs.read('/tmp/fwmon/panel.json'), '{}');
	},

	render: function (raw) {
		var p = parse(raw);
		var alerts = p.alerts || [];

		var rows = alerts.map(function (a) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, String(a.ts ? new Date(a.ts * 1000).toLocaleString() : '')),
				E('td', { 'class': 'td' }, [
					E('span', {
						'style': 'color:#fff;background:' + (SEV[a.severity] || '#5f5e5a') +
							';padding:1px 6px;border-radius:3px;font-size:11px;'
					}, a.severity)
				]),
				E('td', { 'class': 'td' }, TYPE[a.type] || a.type),
				E('td', { 'class': 'td' }, a.src),
				E('td', { 'class': 'td' }, (a.metric || '') + '=' + (a.value || 0) + ' / ' + (a.threshold || 0)),
				E('td', { 'class': 'td' }, a.detail || '')
			]);
		});

		var table = E('table', { 'class': 'table cbi-section-table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, '时间'),
				E('th', { 'class': 'th' }, '级别'),
				E('th', { 'class': 'th' }, '类型'),
				E('th', { 'class': 'th' }, '源 IP'),
				E('th', { 'class': 'th' }, '指标'),
				E('th', { 'class': 'th' }, '详情')
			]),
			E('tbody', {}, rows.length ? rows : [
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': '6' }, '暂无告警')])
			])
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, '入站监控 · 事件告警'),
			E('p', { 'class': 'cbi-section-descr' }, '检测规则：扫描 / 泛洪 / 暴破 / 突增 / 丢弃异常 / 惯犯。'),
			table
		]);
	}
});
