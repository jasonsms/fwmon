'use strict';
'require view';
'require fs';
'require ui';

function fmt(n) { return Number(n || 0).toLocaleString(); }
function parse(raw) { try { return JSON.parse(raw); } catch (e) { return {}; } }

function topPorts(it) {
	var arr = it.top_ports || [];
	return arr.map(function (p) { return p.dport + '(' + p.n + ')'; }).join(' ') || '-';
}

function flags(it) {
	var f = it.flags || {};
	var out = [];
	if (f.scan) out.push('扫描');
	if (f.flood) out.push('泛洪');
	if (f.bruteforce) out.push('暴破');
	if (f.repeat) out.push('惯犯');
	return out.join(',') || '-';
}

return view.extend({
	load: function () {
		return L.resolveDefault(fs.read('/tmp/fwmon/panel.json'), '{}');
	},

	render: function (raw) {
		var p = parse(raw);
		var items = (p.ips || []).slice(0, 300);
		var self = this;

		var rows = items.map(function (it) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, it.src),
				E('td', { 'class': 'td' }, fmt(it.events)),
				E('td', { 'class': 'td' }, fmt(it.accept) + ' / ' + fmt(it.drop)),
				E('td', { 'class': 'td' }, topPorts(it)),
				E('td', { 'class': 'td' }, flags(it)),
				E('td', { 'class': 'td' }, String(it.last_seen || '').replace('T', ' ').slice(0, 19)),
				E('td', { 'class': 'td' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-negative',
						'click': ui.createHandlerFn(self, 'handleBlock', it.src, true)
					}, '拉黑'),
					' ',
					E('button', {
						'class': 'btn cbi-button',
						'click': ui.createHandlerFn(self, 'handleBlock', it.src, false)
					}, '解除')
				])
			]);
		});

		var table = E('table', { 'class': 'table cbi-section-table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, '源 IP'),
				E('th', { 'class': 'th' }, '事件'),
				E('th', { 'class': 'th' }, '放行/丢弃'),
				E('th', { 'class': 'th' }, 'Top 端口(次数)'),
				E('th', { 'class': 'th' }, '标记'),
				E('th', { 'class': 'th' }, '最近'),
				E('th', { 'class': 'th' }, '动作')
			]),
			E('tbody', {}, rows.length ? rows : [
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': '7' }, '暂无数据')])
			])
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, '入站监控 · 攻击者 IP'),
			E('p', { 'class': 'cbi-section-descr' },
				'按事件数排序的入站源。拉黑需在设置中开启“自动拉黑”。'),
			table
		]);
	},

	handleBlock: function (src, enable) {
		var self = this;
		return fs.exec('/usr/lib/fwmon/' + (enable ? 'block.sh' : 'unblock.sh'), [src]).then(function () {
			ui.addNotification(null, E('p', {}, (enable ? '已请求拉黑 ' : '已解除 ') + src), 'info');
		}).catch(function (e) {
			ui.addNotification(null, E('p', {}, '操作失败：' + e.message), 'warning');
		});
	}
});
