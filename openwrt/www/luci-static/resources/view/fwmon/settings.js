'use strict';
'require view';
'require fs';
'require uci';
'require ui';

function row(label, id, value, type, hint) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('input', {
				'id': id,
				'type': type || 'text',
				'class': 'cbi-input-text',
				'value': value == null ? '' : String(value)
			}),
			hint ? E('div', { 'class': 'cbi-value-description' }, hint) : null
		])
	]);
}

function checkRow(label, id, value, hint) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, label),
		E('div', { 'class': 'cbi-value-field' }, [
			E('input', { 'id': id, 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'checked': value ? 'checked' : null }),
			hint ? E('div', { 'class': 'cbi-value-description' }, hint) : null
		])
	]);
}

function val(id) { var e = document.getElementById(id); return e ? e.value : ''; }
function chk(id) { var e = document.getElementById(id); return e && e.checked; }

return view.extend({
	load: function () {
		return uci.load('fwmon');
	},

	render: function () {
		var self = this;
		var g = function (s, o, d) { var v = uci.get('fwmon', s, o); return v == null ? d : v; };

		var body = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, '基本'),
			checkRow('启用', 'fwmon_enabled', g('main', 'enabled', '1') === '1'),
			row('放行端口 (fn-knock 网关)', 'fwmon_exposed_port', g('main', 'exposed_port', '443'), 'text', '你对外开放的唯一端口'),
			row('保留天数', 'fwmon_retention_days', g('main', 'retention_days', '90'), 'text'),
			row('每日原始上限 (MB)', 'fwmon_raw_max_mb', g('main', 'raw_max_mb', '30'), 'text', '存于 /tmp(RAM)，超出丢弃'),

			E('h3', {}, '告警通知 · 微信 PushPlus'),
			checkRow('启用通知', 'fwmon_notify', g('main', 'notify', '0') === '1'),
			row('PushPlus Token', 'fwmon_token', g('main', 'pushplus_token', ''), 'password', '在 pushplus.plus 获取，仅存本机'),
			row('最低通知级别', 'fwmon_min_sev', g('main', 'notify_min_severity', 'warn'), 'text', 'info / warn / high / critical'),

			E('h3', {}, '自动拉黑'),
			checkRow('自动拉黑 (high+)', 'fwmon_auto_block', g('main', 'auto_block', '0') === '1', '默认关闭；开启后对高频源 REJECT'),

			E('h3', {}, '检测阈值'),
			row('端口扫描阈值 (个端口)', 'fwmon_scan_ports', g('thresholds', 'scan_ports', '15')),
			row('连接泛洪阈值 (次/分钟)', 'fwmon_flood', g('thresholds', 'flood_per_min', '300')),
			row('暴破阈值 (次/窗口秒)', 'fwmon_bf_count', g('thresholds', 'bruteforce_count', '60')),
			row('暴破窗口 (秒)', 'fwmon_bf_window', g('thresholds', 'bruteforce_window', '120')),
			row('去抖冷却 (秒)', 'fwmon_cooldown', g('thresholds', 'cooldown', '600'))
		]);

		var saveBtn = E('button', {
			'class': 'btn cbi-button cbi-button-save',
			'click': ui.createHandlerFn(self, 'handleSave')
		}, '保存并应用');

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, '入站监控 · 设置'),
			body,
			E('div', { 'class': 'cbi-page-actions' }, [saveBtn])
		]);
	},

	handleSave: function () {
		function s(sec, opt, value) { uci.set('fwmon', sec, opt, value); }
		s('main', 'enabled', chk('fwmon_enabled') ? '1' : '0');
		s('main', 'exposed_port', val('fwmon_exposed_port') || '443');
		s('main', 'retention_days', val('fwmon_retention_days') || '90');
		s('main', 'raw_max_mb', val('fwmon_raw_max_mb') || '30');
		s('main', 'notify', chk('fwmon_notify') ? '1' : '0');
		s('main', 'pushplus_token', val('fwmon_token'));
		s('main', 'notify_min_severity', val('fwmon_min_sev') || 'warn');
		s('main', 'auto_block', chk('fwmon_auto_block') ? '1' : '0');
		s('thresholds', 'scan_ports', val('fwmon_scan_ports') || '15');
		s('thresholds', 'flood_per_min', val('fwmon_flood') || '300');
		s('thresholds', 'bruteforce_count', val('fwmon_bf_count') || '60');
		s('thresholds', 'bruteforce_window', val('fwmon_bf_window') || '120');
		s('thresholds', 'cooldown', val('fwmon_cooldown') || '600');

		return uci.save().then(function () {
			return fs.exec('/etc/init.d/fwmon', ['restart']);
		}).then(function () {
			ui.addNotification(null, E('p', {}, '设置已保存并重启 fwmon。'), 'info');
		}).catch(function (e) {
			ui.addNotification(null, E('p', {}, '保存失败：' + e.message), 'warning');
		});
	}
});
