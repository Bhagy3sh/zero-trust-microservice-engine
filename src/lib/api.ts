// ZeroTrust Mesh - Tauri API wrapper

import { invoke } from '@tauri-apps/api/core';

// Types
export interface Service {
	id: string;
	spiffe_id: string;
	name: string;
	description?: string;
	port: number;
	status: string;
	trust_score: number;
}

export interface Policy {
	id: string;
	name: string;
	description?: string;
	priority: number;
	enabled: boolean;
	conditions: any[];
	action: string;
	hit_count: number;
	last_match?: string;
}

export interface TrustScore {
	service_id: string;
	score: number;
	level: string;
	tpm_score: number;
	process_score: number;
	behavioral_score: number;
	resource_score: number;
	reason?: string;
	calculated_at: string;
}

export interface Alert {
	id: number;
	alert_type: string;
	severity: string;
	title: string;
	message: string;
	source?: string;
	acknowledged: boolean;
	muted: boolean;
	created_at: string;
}

export interface AttackEvent {
	id: number;
	attack_type: string;
	source_ip: string;
	destination_ip: string;
	severity: string;
	packet_count: number;
	blocked: boolean;
	created_at: string;
}

export interface DashboardData {
	services: {
		total: number;
		active: number;
		healthy: number;
		warning: number;
		critical: number;
	};
	attacks: {
		total_24h: number;
		blocked_24h: number;
		by_hour: Array<{ hour: string; count: number }>;
		top_types: Array<[string, number]>;
	};
	policies: {
		total: number;
		enabled: number;
		recent_hits: number;
	};
	alerts: {
		total: number;
		unacknowledged: number;
		critical: number;
		high: number;
	};
	tunnels: {
		total: number;
		active: number;
		bytes_transferred: number;
	};
}

// Identity API
export const identity = {
	registerService: (request: {
		name: string;
		port: number;
		description?: string;
		binary_path?: string;
	}): Promise<Service> => invoke('register_service', { request }),

	deregisterService: (serviceId: string): Promise<void> =>
		invoke('deregister_service', { serviceId }),

	listServices: (): Promise<Service[]> => invoke('list_services'),

	getService: (serviceId: string): Promise<Service> =>
		invoke('get_service', { serviceId }),

	issueJwtSvid: (serviceId: string, audience: string[]): Promise<string> =>
		invoke('issue_jwt_svid', { serviceId, audience }),

	verifySvid: (token: string): Promise<boolean> =>
		invoke('verify_svid', { token }),
};

// Policy API
export const policy = {
	createPolicy: (request: {
		name: string;
		description?: string;
		priority: number;
		conditions: any;
		action: string;
	}): Promise<Policy> => invoke('create_policy', { request }),

	updatePolicy: (policyId: string, request: any): Promise<Policy> =>
		invoke('update_policy', { policyId, request }),

	deletePolicy: (policyId: string): Promise<void> =>
		invoke('delete_policy', { policyId }),

	listPolicies: (): Promise<Policy[]> => invoke('list_policies'),

	getPolicy: (policyId: string): Promise<Policy> =>
		invoke('get_policy', { policyId }),

	evaluatePolicy: (request: {
		source_spiffe_id?: string;
		source_ip?: string;
		dest_spiffe_id?: string;
		dest_port?: number;
		method?: string;
		trust_score?: number;
	}): Promise<{
		action: string;
		matched_policy_id?: string;
		matched_policy_name?: string;
		deny_reason?: string;
		evaluation_time_us: number;
	}> => invoke('evaluate_policy', { request }),

	togglePolicy: (policyId: string, enabled: boolean): Promise<void> =>
		invoke('toggle_policy', { policyId, enabled }),
};

// Attestation API
export const attestation = {
	getTrustScore: (serviceId: string): Promise<TrustScore> =>
		invoke('get_trust_score', { serviceId }),

	listTrustScores: (): Promise<TrustScore[]> => invoke('list_trust_scores'),

	measureBinary: (path: string): Promise<{
		path: string;
		sha256_hash: string;
		size_bytes: number;
		measured_at: string;
	}> => invoke('measure_binary', { path }),

	getTpmStatus: (): Promise<{
		available: boolean;
		version?: string;
		manufacturer?: string;
		last_check: string;
	}> => invoke('get_tpm_status'),
};

// Attacks API
export const attacks = {
	getStats: (): Promise<{
		total_24h: number;
		blocked_24h: number;
		by_type: Record<string, number>;
		top_attackers: Array<[string, number]>;
		blacklist_count: number;
	}> => invoke('get_attack_stats'),

	getRecentAttacks: (limit?: number): Promise<AttackEvent[]> =>
		invoke('get_recent_attacks', { limit }),

	blacklistIp: (ip: string, reason: string, durationHours?: number): Promise<void> =>
		invoke('blacklist_ip', { ip, reason, durationHours }),

	whitelistIp: (ip: string, description: string): Promise<void> =>
		invoke('whitelist_ip', { ip, description }),

	getBlacklist: (): Promise<Array<{
		ip: string;
		reason: string;
		expires_at?: string;
		created_at: string;
	}>> => invoke('get_blacklist'),
};

// Alerts API
export const alerts = {
	getAlerts: (limit?: number, unacknowledgedOnly?: boolean): Promise<Alert[]> =>
		invoke('get_alerts', { limit, unacknowledgedOnly }),

	acknowledgeAlert: (alertId: number): Promise<void> =>
		invoke('acknowledge_alert', { alertId }),

	muteAlertType: (alertType: string): Promise<void> =>
		invoke('mute_alert_type', { alertType }),
};

// Dashboard API
export const dashboard = {
	getData: (): Promise<DashboardData> => invoke('get_dashboard_data'),

	getServiceTopology: (): Promise<{
		nodes: Array<{
			id: string;
			name: string;
			trust_score: number;
			status: string;
		}>;
		edges: Array<{
			source: string;
			target: string;
			status: string;
		}>;
	}> => invoke('get_service_topology'),
};

// Audit API
export const audit = {
	getLogs: (
		eventType?: string,
		limit?: number,
		offset?: number
	): Promise<Array<{
		id: number;
		event_type: string;
		action: string;
		subject?: string;
		details?: string;
		success: boolean;
		created_at: string;
	}>> => invoke('get_audit_logs', { eventType, limit, offset }),

	exportLogs: (startDate?: string, endDate?: string): Promise<string> =>
		invoke('export_logs', { startDate, endDate }),
};

// Config API
export const config = {
	get: (): Promise<any> => invoke('get_config'),

	update: (section: string, key: string, value: any): Promise<void> =>
		invoke('update_config', { request: { section, key, value } }),
};

// WireGuard API
export const wireguard = {
	createTunnel: (request: {
		service_a_id: string;
		service_b_id: string;
		endpoint?: string;
	}): Promise<any> => invoke('create_tunnel', { request }),

	destroyTunnel: (tunnelId: string): Promise<void> =>
		invoke('destroy_tunnel', { tunnelId }),

	listTunnels: (): Promise<any[]> => invoke('list_tunnels'),

	getTunnelStatus: (tunnelId: string): Promise<any> =>
		invoke('get_tunnel_status', { tunnelId }),
};
