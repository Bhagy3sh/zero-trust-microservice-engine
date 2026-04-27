<script lang="ts">
	import { onMount } from 'svelte';
	import { currentSection, type NavigationSection } from '$lib/navigation';
	import { scanStore } from '$lib/scanStore';
	import {
		alerts,
		attacks,
		audit,
		attestation,
		config,
		dashboard,
		dev,
		identity,
		policy,
		wireguard,
		type Alert,
		type AttackEvent,
		type AuditLog,
		type ConfigResponse,
		type DashboardData,
		type DatabaseStats,
		type Policy,
		type Service,
		type ServiceScanSummary,
		type TpmStatus,
		type Tunnel
	} from '$lib/api';
	import {
		Activity, AlertTriangle, FileText, Lock, Network, Server, Settings,
		ChevronDown, ChevronRight, Zap, Plus, Eye, Ban, CheckCheck, Download
	} from 'lucide-svelte';

	type AttackStats = {
		total_24h: number;
		blocked_24h: number;
		by_type: Array<[string, number]>;
		top_attackers: Array<[string, number]>;
		blacklist_count: number;
	};

	type BlacklistEntry = {
		ip: string;
		reason: string;
		expires_at?: string;
		created_at: string;
	};

	type ServiceTopology = {
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
	};

	type ServiceRegistrationForm = {
		name: string;
		port: number;
		description: string;
		binary_path: string;
	};

	type TunnelForm = {
		service_a_id: string;
		service_b_id: string;
		endpoint: string;
	};

	const sectionMeta: Record<NavigationSection, { title: string; description: string }> = {
		dashboard: {
			title: 'Dashboard',
			description: 'Live database-backed overview of the current zero-trust workspace.'
		},
		services: {
			title: 'Services',
			description: 'Register workloads and inspect currently known service identities.'
		},
		policies: {
			title: 'Policies',
			description: 'Review persisted policy rules and their enforcement metadata.'
		},
		mesh: {
			title: 'Mesh',
			description: 'Inspect topology and persisted tunnel records for the service mesh.'
		},
		attacks: {
			title: 'Attacks',
			description: 'Review recorded attack events, blacklist entries, and alert state.'
		},
		audit: {
			title: 'Audit',
			description: 'Inspect audit history captured by the desktop backend.'
		},
		settings: {
			title: 'Settings',
			description: 'See runtime paths, environment status, and effective configuration.'
		}
	};

	let activeSection: NavigationSection = 'dashboard';
	let hasMounted = false;
	let isLoading = false;
	let isSeeding = false;
	let isRegisteringService = false;
	let isCreatingTunnel = false;
	let isScanningServices = false;
	let actionMessage = '';
	let errorMessage = '';

	// Per-service expand state
	let expandedServiceId: string | null = null;

	// JWT-SVID issuance
	let jwtSvidTokens: Record<string, string> = {};
	let isIssuingJwt: string | null = null;

	// Policy evaluator
	let policyEvalForm = { source_spiffe_id: '', source_service_name: '', dest_spiffe_id: '', dest_service_name: '', source_ip: '', dest_port: 0, trust_score: 0.8 };
	let policyEvalResult: { action: string; matched_policy_name?: string; deny_reason?: string; evaluation_time_us: number } | null = null;
	let isEvaluatingPolicy = false;

	// Policy create
	let createPolicyForm = { name: '', priority: 10, action: 'Allow', condition_type: 'trust_score', threshold: 0.5 };
	let isCreatingPolicy = false;
	let showCreatePolicy = false;

	// Blacklist form
	let blacklistForm = { ip: '', reason: '', duration_hours: '' };
	let isBlacklistingIp = false;

	// Alert acknowledge
	let isAcknowledgingAlertId: number | null = null;

	// Audit filter
	let auditFilter = '';
	let isExportingLogs = false;

	let dashboardData: DashboardData = {
		services: { total: 0, active: 0, healthy: 0, warning: 0, critical: 0 },
		attacks: { total_24h: 0, blocked_24h: 0, by_hour: [], top_types: [] },
		policies: { total: 0, enabled: 0, recent_hits: 0 },
		alerts: { total: 0, unacknowledged: 0, critical: 0, high: 0 },
		tunnels: { total: 0, active: 0, bytes_transferred: 0 }
	};
	let services: Service[] = [];
	let recentAlerts: Alert[] = [];
	let policies: Policy[] = [];
	let tunnels: Tunnel[] = [];
	let topology: ServiceTopology = { nodes: [], edges: [] };
	let attackStats: AttackStats = {
		total_24h: 0,
		blocked_24h: 0,
		by_type: [],
		top_attackers: [],
		blacklist_count: 0
	};
	let recentAttacks: AttackEvent[] = [];
	let blacklist: BlacklistEntry[] = [];
	let auditLogs: AuditLog[] = [];
	let configData: ConfigResponse | null = null;
	let databaseStats: DatabaseStats | null = null;
	let tpmStatus: TpmStatus | null = null;
	let lastServiceScanSummary: ServiceScanSummary | null = null;

	let serviceForm: ServiceRegistrationForm = {
		name: '',
		port: 8080,
		description: '',
		binary_path: ''
	};
	let tunnelForm: TunnelForm = {
		service_a_id: '',
		service_b_id: '',
		endpoint: ''
	};

	onMount(async () => {
		hasMounted = true;
		// Auto-scan on startup if services exist (silent background scan)
		try {
			const svcs = await identity.listServices();
			if (svcs.length > 0 && !lastServiceScanSummary) {
				await runServiceScans(true);
			}
		} catch { /* silent */ }
	});

	$: activeSection = $currentSection;
	$: if (hasMounted) {
		void refreshSection(activeSection);
	}

	async function refreshSection(section: NavigationSection = activeSection) {
		isLoading = true;
		errorMessage = '';

		try {
			switch (section) {
				case 'dashboard':
					await loadDashboardSection();
					break;
				case 'services':
					await loadServicesSection();
					break;
				case 'policies':
					await loadPoliciesSection();
					break;
				case 'mesh':
					await loadMeshSection();
					break;
				case 'attacks':
					await loadAttacksSection();
					break;
				case 'audit':
					await loadAuditSection();
					break;
				case 'settings':
					await loadSettingsSection();
					break;
			}
		} catch (error) {
			console.error(error);
			errorMessage = error instanceof Error ? error.message : 'Failed to load section data';
		} finally {
			isLoading = false;
		}
	}

	async function loadDashboardSection() {
		const [dashboardResponse, servicesResponse, alertsResponse, statsResponse, tpmResponse] =
			await Promise.all([
				dashboard.getData(),
				identity.listServices(),
				alerts.getAlerts(4, false),
				config.getDatabaseStats(),
				attestation.getTpmStatus()
			]);

		dashboardData = dashboardResponse;
		services = servicesResponse;
		recentAlerts = alertsResponse;
		databaseStats = statsResponse;
		tpmStatus = tpmResponse;
	}

	async function loadServicesSection() {
		const [servicesResponse, statsResponse] = await Promise.all([
			identity.listServices(),
			config.getDatabaseStats()
		]);

		services = servicesResponse;
		databaseStats = statsResponse;
		if (!tunnelForm.service_a_id && servicesResponse.length > 0) {
			tunnelForm.service_a_id = servicesResponse[0].id;
		}
		if (!tunnelForm.service_b_id && servicesResponse.length > 1) {
			tunnelForm.service_b_id = servicesResponse[1].id;
		}
	}

	async function loadPoliciesSection() {
		const [policiesResponse, dashboardResponse] = await Promise.all([
			policy.listPolicies(),
			dashboard.getData()
		]);

		policies = policiesResponse;
		dashboardData = dashboardResponse;
	}

	async function loadMeshSection() {
		const [topologyResponse, tunnelsResponse, servicesResponse] = await Promise.all([
			dashboard.getServiceTopology(),
			wireguard.listTunnels(),
			identity.listServices()
		]);

		topology = topologyResponse;
		tunnels = tunnelsResponse;
		services = servicesResponse;

		if (!tunnelForm.service_a_id && servicesResponse.length > 0) {
			tunnelForm.service_a_id = servicesResponse[0].id;
		}
		if (!tunnelForm.service_b_id && servicesResponse.length > 1) {
			tunnelForm.service_b_id = servicesResponse[1].id;
		}
	}

	async function loadAttacksSection() {
		const [attackStatsResponse, attacksResponse, blacklistResponse, alertsResponse] = await Promise.all([
			attacks.getStats(),
			attacks.getRecentAttacks(20),
			attacks.getBlacklist(),
			alerts.getAlerts(8, false)
		]);

		attackStats = attackStatsResponse;
		recentAttacks = attacksResponse;
		blacklist = blacklistResponse;
		recentAlerts = alertsResponse;
	}

	async function loadAuditSection() {
		auditLogs = await audit.getLogs(undefined, 100, 0);
	}

	async function loadSettingsSection() {
		const [configResponse, statsResponse, tpmResponse] = await Promise.all([
			config.get(),
			config.getDatabaseStats(),
			attestation.getTpmStatus()
		]);

		configData = configResponse;
		databaseStats = statsResponse;
		tpmStatus = tpmResponse;
	}

	async function loadDemoData() {
		isSeeding = true;
		errorMessage = '';

		try {
			const result = await dev.seedDemoData();
			actionMessage = `Loaded demo data: ${result.services} services, ${result.policies} policies, ${result.attacks} attacks, ${result.alerts} alerts.`;
			await refreshSection(activeSection);
		} catch (error) {
			console.error(error);
			errorMessage = error instanceof Error ? error.message : 'Failed to load demo data';
		} finally {
			isSeeding = false;
		}
	}

	async function registerService() {
		if (!serviceForm.name.trim()) {
			errorMessage = 'Service name is required.';
			return;
		}

		isRegisteringService = true;
		errorMessage = '';

		try {
			await identity.registerService({
				name: serviceForm.name.trim(),
				port: Number(serviceForm.port),
				description: serviceForm.description.trim() || undefined,
				binary_path: serviceForm.binary_path.trim() || undefined
			});
			actionMessage = `Registered service "${serviceForm.name.trim()}".`;
			serviceForm = { name: '', port: 8080, description: '', binary_path: '' };
			await loadServicesSection();
		} catch (error) {
			console.error(error);
			errorMessage = error instanceof Error ? error.message : 'Failed to register service';
		} finally {
			isRegisteringService = false;
		}
	}

	async function runServiceScans(silent = false) {
		isScanningServices = true;
		scanStore.update(s => ({ ...s, isScanning: true }));
		if (!silent) errorMessage = '';

		try {
			const summary = await attestation.scanRegisteredServices();
			lastServiceScanSummary = summary;
			scanStore.update(s => ({
				...s,
				lastScanSummary: summary,
				lastScanTime: new Date().toISOString(),
				isScanning: false
			}));
			if (!silent) {
				actionMessage =
					summary.scanned === 0
						? 'No active services are registered yet, so there was nothing to scan.'
						: `Scan complete: ${summary.passed} passed, ${summary.failed} failed, ${summary.skipped} skipped.`;
			}
			await refreshSection(activeSection);
		} catch (error) {
			scanStore.update(s => ({ ...s, isScanning: false }));
			console.error(error);
			if (!silent) errorMessage = error instanceof Error ? error.message : 'Failed to run service scans';
		} finally {
			isScanningServices = false;
		}
	}

	async function doIssueJwtSvid(serviceId: string) {
		isIssuingJwt = serviceId;
		try {
			const token = await identity.issueJwtSvid(serviceId, ['zerotrust.local']);
			jwtSvidTokens = { ...jwtSvidTokens, [serviceId]: token };
			actionMessage = 'JWT-SVID issued successfully.';
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to issue JWT-SVID';
		} finally {
			isIssuingJwt = null;
		}
	}

	async function doEvaluatePolicy() {
		isEvaluatingPolicy = true;
		policyEvalResult = null;
		try {
			policyEvalResult = await policy.evaluatePolicy({
				source_spiffe_id: policyEvalForm.source_spiffe_id || undefined,
				source_service_name: policyEvalForm.source_service_name || undefined,
				dest_spiffe_id: policyEvalForm.dest_spiffe_id || undefined,
				dest_service_name: policyEvalForm.dest_service_name || undefined,
				source_ip: policyEvalForm.source_ip || undefined,
				dest_port: policyEvalForm.dest_port || undefined,
				trust_score: policyEvalForm.trust_score
			});
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Policy evaluation failed';
		} finally {
			isEvaluatingPolicy = false;
		}
	}

	async function doCreatePolicy() {
		if (!createPolicyForm.name.trim()) { errorMessage = 'Policy name is required.'; return; }
		isCreatingPolicy = true;
		try {
			// Rust PolicyCondition uses internally-tagged serde: { type: "risk_score", ... }
			// Operator enum uses snake_case: "less_than" not "LessThan"
			const condition = createPolicyForm.condition_type === 'trust_score'
				? { type: 'risk_score', operator: 'less_than', threshold: Number(createPolicyForm.threshold) }
				: null;
			await policy.createPolicy({
				name: createPolicyForm.name.trim(),
				priority: Number(createPolicyForm.priority),
				action: createPolicyForm.action,
				conditions: condition ? [condition] : []
			});
			actionMessage = `Policy "${createPolicyForm.name}" created.`;
			createPolicyForm = { name: '', priority: 10, action: 'Allow', condition_type: 'trust_score', threshold: 0.5 };
			showCreatePolicy = false;
			await loadPoliciesSection();
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to create policy';
		} finally {
			isCreatingPolicy = false;
		}
	}

	async function doBlacklistIp() {
		if (!blacklistForm.ip.trim() || !blacklistForm.reason.trim()) {
			errorMessage = 'IP address and reason are required.';
			return;
		}
		isBlacklistingIp = true;
		try {
			const hours = blacklistForm.duration_hours ? Number(blacklistForm.duration_hours) : undefined;
			await attacks.blacklistIp(blacklistForm.ip.trim(), blacklistForm.reason.trim(), hours);
			actionMessage = `IP ${blacklistForm.ip} blacklisted.`;
			blacklistForm = { ip: '', reason: '', duration_hours: '' };
			await loadAttacksSection();
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to blacklist IP';
		} finally {
			isBlacklistingIp = false;
		}
	}

	async function doAcknowledgeAlert(alertId: number) {
		isAcknowledgingAlertId = alertId;
		try {
			await alerts.acknowledgeAlert(alertId);
			await loadAttacksSection();
			if (activeSection === 'dashboard') await loadDashboardSection();
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to acknowledge alert';
		} finally {
			isAcknowledgingAlertId = null;
		}
	}

	async function doExportLogs() {
		isExportingLogs = true;
		try {
			const path = await audit.exportLogs();
			actionMessage = `Audit logs exported to: ${path}`;
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Export failed';
		} finally {
			isExportingLogs = false;
		}
	}

	async function loadFilteredAudit() {
		try {
			auditLogs = await audit.getLogs(auditFilter || undefined, 100, 0);
		} catch { /* ignore */ }
	}

	async function createTunnel() {
		if (!tunnelForm.service_a_id || !tunnelForm.service_b_id) {
			errorMessage = 'Select two services before creating a tunnel.';
			return;
		}
		if (tunnelForm.service_a_id === tunnelForm.service_b_id) {
			errorMessage = 'Choose two different services for the tunnel.';
			return;
		}

		isCreatingTunnel = true;
		errorMessage = '';

		try {
			await wireguard.createTunnel({
				service_a_id: tunnelForm.service_a_id,
				service_b_id: tunnelForm.service_b_id,
				endpoint: tunnelForm.endpoint.trim() || undefined
			});
			actionMessage = 'Created a persisted tunnel record for the selected services.';
			tunnelForm.endpoint = '';
			await loadMeshSection();
		} catch (error) {
			console.error(error);
			errorMessage = error instanceof Error ? error.message : 'Failed to create tunnel';
		} finally {
			isCreatingTunnel = false;
		}
	}

	function getTrustColor(score: number): string {
		if (score >= 0.8) return 'bg-green-500';
		if (score >= 0.5) return 'bg-yellow-500';
		if (score >= 0.3) return 'bg-orange-500';
		return 'bg-red-500';
	}

	function getSeverityClass(severity: string): string {
		switch (severity.toLowerCase()) {
			case 'critical':
				return 'text-red-400';
			case 'high':
				return 'text-orange-400';
			case 'medium':
				return 'text-yellow-400';
			case 'low':
				return 'text-green-400';
			default:
				return 'text-blue-400';
		}
	}

	function getStatusBadgeClass(status: string): string {
		switch (status.toLowerCase()) {
			case 'active':
				return 'badge badge-success';
			case 'connecting':
				return 'badge badge-warning';
			case 'error':
			case 'inactive':
			case 'terminated':
				return 'badge badge-danger';
			default:
				return 'badge badge-info';
		}
	}

	function getScanStatusBadgeClass(status: string): string {
		switch (status.toLowerCase()) {
			case 'passed':
				return 'badge badge-success';
			case 'failed':
				return 'badge badge-danger';
			case 'skipped':
				return 'badge badge-warning';
			default:
				return 'badge badge-info';
		}
	}

	function formatBytes(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
	}

	function formatDate(value?: string): string {
		if (!value) return 'N/A';
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
	}

	function serviceName(serviceId: string): string {
		return services.find((service) => service.id === serviceId)?.name ?? serviceId;
	}

	function getLatestScanResult(serviceId: string) {
		return lastServiceScanSummary?.results.find((result) => result.service_id === serviceId);
	}
</script>

<div class="p-6 space-y-6">
	<div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
		<div>
			<h1 class="text-2xl font-bold text-slate-100">{sectionMeta[activeSection].title}</h1>
			<p class="text-slate-400">{sectionMeta[activeSection].description}</p>
		</div>
		<div class="flex flex-wrap gap-3">
			<button class="btn btn-secondary" on:click={() => refreshSection(activeSection)} disabled={isLoading}>
				{isLoading ? 'Refreshing...' : 'Refresh'}
			</button>
			{#if activeSection === 'dashboard' || activeSection === 'services'}
				<button class="btn btn-primary flex items-center gap-2" on:click={() => runServiceScans()} disabled={isScanningServices}>
					<Zap class="h-4 w-4" />
					{isScanningServices ? 'Scanning...' : 'Scan All Services'}
				</button>
			{/if}
		</div>
	</div>

	<!-- Live status bar replacing old blue banner -->
	{#if $scanStore.lastScanSummary}
		<div class="flex items-center gap-4 rounded-lg border px-4 py-3 text-sm
			{$scanStore.lastScanSummary.failed > 0
				? 'border-red-500/30 bg-red-950/30 text-red-100'
				: 'border-green-500/30 bg-green-950/30 text-green-100'}">
			<span class="font-medium">Last scan:</span>
			<span>{$scanStore.lastScanSummary.scanned} services —
				{$scanStore.lastScanSummary.passed} passed
				{#if $scanStore.lastScanSummary.failed > 0}
					· <span class="font-semibold">{$scanStore.lastScanSummary.failed} FAILED</span>
				{/if}
				{#if $scanStore.lastScanSummary.skipped > 0}
					· {$scanStore.lastScanSummary.skipped} skipped
				{/if}
			</span>
			{#if $scanStore.lastScanTime}
				<span class="ml-auto text-xs opacity-70">{new Date($scanStore.lastScanTime).toLocaleTimeString()}</span>
			{/if}
		</div>
	{:else if !isScanningServices}
		<div class="rounded-lg border border-slate-600/40 bg-slate-800/40 px-4 py-3 text-sm text-slate-400">
			No scan has run yet. Click <strong class="text-slate-200">Scan All Services</strong> to measure binary hashes and refresh trust scores, or go to <strong class="text-slate-200">Settings → Development Tools</strong> to load a demo workspace.
		</div>
	{:else}
		<div class="rounded-lg border border-blue-500/30 bg-blue-950/30 px-4 py-3 text-sm text-blue-200">
			Scanning services — measuring SHA-256 hashes and updating trust scores…
		</div>
	{/if}

	{#if actionMessage}
		<div class="rounded-lg border border-green-500/30 bg-green-950/30 px-4 py-3 text-sm text-green-100">
			{actionMessage}
		</div>
	{/if}

	{#if errorMessage}
		<div class="rounded-lg border border-red-500/30 bg-red-950/30 px-4 py-3 text-sm text-red-100">
			{errorMessage}
		</div>
	{/if}

	{#if activeSection === 'dashboard'}
		<div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
			<div class="card">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-slate-400">Active Services</p>
						<p class="text-2xl font-bold text-slate-100">{dashboardData.services.active}</p>
					</div>
					<div class="rounded-lg bg-blue-900/30 p-3">
						<Server class="h-6 w-6 text-blue-400" />
					</div>
				</div>
				<div class="mt-4 flex gap-4 text-sm">
					<span class="text-green-400">{dashboardData.services.healthy} healthy</span>
					<span class="text-yellow-400">{dashboardData.services.warning} warning</span>
				</div>
			</div>

			<div class="card">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-slate-400">Attacks (24h)</p>
						<p class="text-2xl font-bold text-slate-100">{dashboardData.attacks.total_24h}</p>
					</div>
					<div class="rounded-lg bg-red-900/30 p-3">
						<AlertTriangle class="h-6 w-6 text-red-400" />
					</div>
				</div>
				<div class="mt-4 text-sm text-slate-400">
					{dashboardData.attacks.blocked_24h} blocked
				</div>
			</div>

			<div class="card">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-slate-400">Active Policies</p>
						<p class="text-2xl font-bold text-slate-100">{dashboardData.policies.enabled}</p>
					</div>
					<div class="rounded-lg bg-purple-900/30 p-3">
						<Lock class="h-6 w-6 text-purple-400" />
					</div>
				</div>
				<div class="mt-4 text-sm text-slate-400">
					{dashboardData.policies.recent_hits.toLocaleString()} policy hits
				</div>
			</div>

			<div class="card">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-slate-400">WireGuard Tunnels</p>
						<p class="text-2xl font-bold text-slate-100">{dashboardData.tunnels.active}</p>
					</div>
					<div class="rounded-lg bg-cyan-900/30 p-3">
						<Network class="h-6 w-6 text-cyan-400" />
					</div>
				</div>
				<div class="mt-4 text-sm text-slate-400">
					{formatBytes(dashboardData.tunnels.bytes_transferred)} transferred
				</div>
			</div>
		</div>

		<div class="grid grid-cols-1 gap-6 xl:grid-cols-3">
			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Services</h2>
					<span class="text-sm text-slate-400">{services.length} total</span>
				</div>
				<div class="space-y-3">
					{#if services.length === 0}
						<p class="text-sm text-slate-400">No services are registered yet.</p>
					{:else}
						{#each services as service}
							<div class="rounded-lg bg-slate-700/30 p-3">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-3">
										<div class={`h-2 w-2 rounded-full ${getTrustColor(service.trust_score)}`}></div>
										<div>
											<p class="font-medium text-slate-100">{service.name}</p>
											<p class="text-xs text-slate-400">{service.spiffe_id}</p>
										</div>
									</div>
									<span class={getStatusBadgeClass(service.status)}>{service.status}</span>
								</div>
							</div>
						{/each}
					{/if}
				</div>
			</div>

			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Attack Types</h2>
					<Activity class="h-5 w-5 text-slate-400" />
				</div>
				<div class="space-y-4">
					{#if dashboardData.attacks.top_types.length === 0}
						<p class="text-sm text-slate-400">No attack records are stored yet.</p>
					{:else}
						{#each dashboardData.attacks.top_types as [type, count]}
							<div>
								<div class="mb-1 flex justify-between text-sm">
									<span class="text-slate-300">{type}</span>
									<span class="text-slate-400">{count}</span>
								</div>
								<div class="h-2 overflow-hidden rounded-full bg-slate-700">
									<div
										class="h-full rounded-full bg-red-500"
										style={`width: ${
											dashboardData.attacks.total_24h > 0
												? (count / dashboardData.attacks.total_24h) * 100
												: 0
										}%`}
									></div>
								</div>
							</div>
						{/each}
					{/if}
				</div>
			</div>

			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Recent Alerts</h2>
					<span class="badge badge-danger">{dashboardData.alerts.unacknowledged} new</span>
				</div>
				<div class="space-y-3">
					{#if recentAlerts.length === 0}
						<p class="text-sm text-slate-400">No alerts available yet.</p>
					{:else}
						{#each recentAlerts as alert}
							<div class="rounded-lg border border-slate-700 bg-slate-700/30 p-3">
								<div class="mb-1 flex items-center justify-between">
									<p class={`text-sm font-medium ${getSeverityClass(alert.severity)}`}>{alert.title}</p>
									<span class="text-xs text-slate-500">{formatDate(alert.created_at)}</span>
								</div>
								<p class="text-xs text-slate-400">{alert.message}</p>
							</div>
						{/each}
					{/if}
				</div>
			</div>
		</div>

		<div class="grid grid-cols-1 gap-6 xl:grid-cols-2">
			<div class="card">
				<div class="card-header">
					<h2 class="card-title">Runtime Snapshot</h2>
					<Settings class="h-5 w-5 text-slate-400" />
				</div>
				<div class="grid grid-cols-1 gap-3 md:grid-cols-2">
					<div class="rounded-lg bg-slate-700/30 p-3">
						<p class="text-xs uppercase tracking-wide text-slate-400">Database rows</p>
						<p class="mt-2 text-sm text-slate-100">
							{databaseStats ? `${databaseStats.service_count} services, ${databaseStats.policy_count} policies, ${databaseStats.tunnel_count} tunnels` : 'Loading...'}
						</p>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-3">
						<p class="text-xs uppercase tracking-wide text-slate-400">TPM Mode</p>
						<p class="mt-2 text-sm text-slate-100">
							{#if tpmStatus?.available}
								Hardware TPM available
							{:else}
								Software fallback active
							{/if}
						</p>
					</div>
				</div>
			</div>

			<div class="card">
				<div class="card-header">
					<h2 class="card-title">Current Build Notes</h2>
					<FileText class="h-5 w-5 text-slate-400" />
				</div>
				<ul class="space-y-2 text-sm text-slate-300">
					<li>Services, policies, alerts, attacks, audit logs, and tunnel records are read from SQLite.</li>
					<li>Manual service attestation scans are available from the Run Service Scan action.</li>
					<li>Live network scanning and packet detection are not auto-started in this desktop build.</li>
					<li>Use Load Demo Data to inspect the intended workflows with representative records.</li>
				</ul>
			</div>
		</div>
	{:else if activeSection === 'services'}
		<div class="grid grid-cols-1 gap-6 xl:grid-cols-3">
			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Register Service</h2>
					<Server class="h-5 w-5 text-slate-400" />
				</div>
				<form class="space-y-4" on:submit|preventDefault={registerService}>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="service-name">Service Name</label>
						<input id="service-name" class="input" bind:value={serviceForm.name} placeholder="API Gateway" />
					</div>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="service-port">Port</label>
						<input id="service-port" class="input" bind:value={serviceForm.port} min="1" max="65535" type="number" />
					</div>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="service-description">Description</label>
						<textarea id="service-description" class="input min-h-[90px]" bind:value={serviceForm.description} placeholder="What does this workload do?"></textarea>
					</div>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="service-binary-path">Binary Path (optional)</label>
						<input id="service-binary-path" class="input" bind:value={serviceForm.binary_path} placeholder="/usr/local/bin/service" />
					</div>
					<button class="btn btn-primary w-full" disabled={isRegisteringService}>
						{isRegisteringService ? 'Registering...' : 'Register Service'}
					</button>
				</form>
			</div>

			<div class="card xl:col-span-2">
				<div class="card-header">
					<h2 class="card-title">Known Services</h2>
					<span class="text-sm text-slate-400">{databaseStats?.service_count ?? services.length} active</span>
				</div>
				<div class="mb-4 rounded-lg border border-slate-700 bg-slate-800/50 p-4">
					<div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
						<div>
							<p class="text-sm font-medium text-slate-100">Service Attestation Scan</p>
							<p class="text-sm text-slate-400">
								Run the real backend binary measurement and trust-score refresh for all active registered services in the database.
							</p>
						</div>
						<button class="btn btn-secondary" on:click={runServiceScans} disabled={isScanningServices}>
							{isScanningServices ? 'Scanning...' : 'Run Scan Now'}
						</button>
					</div>

					{#if lastServiceScanSummary}
						<div class="mt-4 grid grid-cols-1 gap-3 md:grid-cols-4">
							<div class="rounded-lg bg-slate-700/40 p-3">
								<p class="text-xs uppercase tracking-wide text-slate-400">Scanned</p>
								<p class="mt-2 text-lg font-semibold text-slate-100">{lastServiceScanSummary.scanned}</p>
							</div>
							<div class="rounded-lg bg-slate-700/40 p-3">
								<p class="text-xs uppercase tracking-wide text-slate-400">Passed</p>
								<p class="mt-2 text-lg font-semibold text-green-400">{lastServiceScanSummary.passed}</p>
							</div>
							<div class="rounded-lg bg-slate-700/40 p-3">
								<p class="text-xs uppercase tracking-wide text-slate-400">Failed</p>
								<p class="mt-2 text-lg font-semibold text-red-400">{lastServiceScanSummary.failed}</p>
							</div>
							<div class="rounded-lg bg-slate-700/40 p-3">
								<p class="text-xs uppercase tracking-wide text-slate-400">Skipped</p>
								<p class="mt-2 text-lg font-semibold text-yellow-400">{lastServiceScanSummary.skipped}</p>
							</div>
						</div>
						<p class="mt-3 text-xs text-slate-500">
							Last run: {formatDate(lastServiceScanSummary.started_at)} to {formatDate(lastServiceScanSummary.completed_at)}
						</p>
					{:else}
						<p class="mt-4 text-sm text-slate-400">
							No scan has been run in this session yet. Scan counts are based on registered services, not all files in the repository.
						</p>
					{/if}
				</div>
				{#if services.length === 0}
					<p class="text-sm text-slate-400">
						No services are registered yet. Use the form or load demo data to populate this view.
					</p>
				{:else}
					<div class="overflow-x-auto">
						<table class="table">
							<thead>
								<tr>
									<th>Name</th>
									<th>SPIFFE ID</th>
									<th>Port</th>
									<th>Status</th>
									<th>Trust</th>
									<th>Binary</th>
									<th>Last Scan</th>
								</tr>
							</thead>
							<tbody>
								{#each services as service}
									{@const scanResult = getLatestScanResult(service.id)}
									{@const isExpanded = expandedServiceId === service.id}
									<tr class="cursor-pointer" on:click={() => expandedServiceId = isExpanded ? null : service.id}>
										<td class="font-medium">
											<div class="flex items-center gap-2">
												{#if isExpanded}<ChevronDown class="h-3.5 w-3.5 text-slate-400 flex-shrink-0" />{:else}<ChevronRight class="h-3.5 w-3.5 text-slate-400 flex-shrink-0" />{/if}
												{service.name}
											</div>
										</td>
										<td class="max-w-[200px] truncate text-slate-300 font-mono text-xs">{service.spiffe_id}</td>
										<td>{service.port}</td>
										<td><span class={getStatusBadgeClass(service.status)}>{service.status}</span></td>
										<td>
											<div class="flex items-center gap-2">
												<div class="h-1.5 w-16 rounded-full bg-slate-700 overflow-hidden">
													<div class="h-full rounded-full {getTrustColor(service.trust_score)}" style="width:{service.trust_score*100}%"></div>
												</div>
												<span>{Math.round(service.trust_score * 100)}%</span>
											</div>
										</td>
										<td class="max-w-[180px] truncate text-slate-300 font-mono text-xs">{service.binary_path ?? '—'}</td>
										<td>
											{#if scanResult}
												<span class={getScanStatusBadgeClass(scanResult.status)}>{scanResult.status}</span>
											{:else}
												<span class="text-slate-500 text-xs">Not run yet</span>
											{/if}
										</td>
									</tr>
									{#if isExpanded}
										<tr class="bg-slate-900/60">
											<td colspan="7" class="px-4 py-4">
												<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
													<div class="space-y-2">
														<p class="text-xs font-semibold uppercase tracking-wide text-slate-400">Binary Attestation</p>
														{#if scanResult}
															<div class="space-y-1 font-mono text-xs">
																<p class="text-slate-400">Measured SHA-256:</p>
																<p class="break-all text-green-300">{scanResult.measured_sha256 ?? 'N/A'}</p>
																<p class="text-slate-400 mt-2">Expected SHA-256:</p>
																<p class="break-all text-slate-300">{scanResult.expected_sha256 ?? 'Not set (first scan stores baseline)'}</p>
																<p class="text-slate-500 mt-2">Measured at: {formatDate(scanResult.measured_at)}</p>
															</div>
														{:else}
															<p class="text-xs text-slate-500">Run a scan to see binary hash details.</p>
														{/if}
													</div>
													<div class="space-y-2">
														<p class="text-xs font-semibold uppercase tracking-wide text-slate-400">Trust Score Detail</p>
														{#if scanResult}
															<div class="space-y-1.5 text-xs">
																{#each [['Trust Level', scanResult.trust_level], ['Score', `${Math.round(scanResult.trust_score * 100)}%`], ['Reason', scanResult.reason ?? '—']] as [label, val]}
																	<div class="flex justify-between">
																		<span class="text-slate-400">{label}</span>
																		<span class="text-slate-200">{val}</span>
																	</div>
																{/each}
															</div>
														{:else}
															<p class="text-xs text-slate-500">No trust score data yet.</p>
														{/if}
													</div>
												</div>
												<div class="mt-4 border-t border-slate-700 pt-4">
													<p class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">JWT-SVID</p>
													<button class="btn btn-primary text-xs" on:click|stopPropagation={() => doIssueJwtSvid(service.id)} disabled={isIssuingJwt === service.id}>
														{isIssuingJwt === service.id ? 'Issuing...' : 'Issue JWT-SVID'}
													</button>
													{#if jwtSvidTokens[service.id]}
														<div class="mt-3 rounded-lg bg-slate-900 p-3">
															<p class="mb-1 text-xs text-slate-400">Token (JWT-SVID):</p>
															<p class="break-all font-mono text-xs text-green-300">{jwtSvidTokens[service.id]}</p>
														</div>
													{/if}
												</div>
											</td>
										</tr>
									{/if}
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeSection === 'policies'}
		<div class="grid grid-cols-1 gap-6 xl:grid-cols-2">
			<!-- Policy List + Create -->
			<div class="space-y-4">
				<div class="card">
					<div class="card-header">
						<h2 class="card-title">Persisted Policies</h2>
						<button class="btn btn-secondary flex items-center gap-1 py-1 px-3 text-sm" on:click={() => showCreatePolicy = !showCreatePolicy}>
							<Plus class="h-4 w-4" /> New Policy
						</button>
					</div>
					{#if showCreatePolicy}
						<form class="mb-4 rounded-lg border border-slate-600 bg-slate-900/50 p-4 space-y-3" on:submit|preventDefault={doCreatePolicy}>
							<p class="text-sm font-semibold text-slate-200">Create Policy</p>
							<div class="grid grid-cols-2 gap-3">
								<div>
									<label class="mb-1 block text-xs text-slate-400" for="cp-name">Name</label>
									<input id="cp-name" class="input" bind:value={createPolicyForm.name} placeholder="Deny Low Trust" />
								</div>
								<div>
									<label class="mb-1 block text-xs text-slate-400" for="cp-priority">Priority</label>
									<input id="cp-priority" class="input" type="number" bind:value={createPolicyForm.priority} min="1" />
								</div>
							</div>
							<div class="grid grid-cols-2 gap-3">
								<div>
									<label class="mb-1 block text-xs text-slate-400" for="cp-action">Action</label>
									<select id="cp-action" class="input" bind:value={createPolicyForm.action}>
										<option>Allow</option>
										<option>Deny</option>
										<option>Log</option>
									</select>
								</div>
								<div>
									<label class="mb-1 block text-xs text-slate-400" for="cp-threshold">Trust Threshold</label>
									<input id="cp-threshold" class="input" type="number" step="0.05" min="0" max="1" bind:value={createPolicyForm.threshold} />
								</div>
							</div>
							<p class="text-xs text-slate-500">Condition: trust score &lt; threshold → apply action</p>
							<button class="btn btn-primary w-full" disabled={isCreatingPolicy}>
								{isCreatingPolicy ? 'Creating...' : 'Create Policy'}
							</button>
						</form>
					{/if}
					{#if policies.length === 0}
						<p class="text-sm text-slate-400">No policies stored yet. Create one above or load a demo workspace from Settings.</p>
					{:else}
						<div class="overflow-x-auto">
							<table class="table">
								<thead><tr><th>Name</th><th>Action</th><th>Priority</th><th>Enabled</th><th>Hits</th></tr></thead>
								<tbody>
									{#each policies as p}
										<tr>
											<td>
												<div class="font-medium text-slate-100">{p.name}</div>
												{#if p.description}<div class="text-xs text-slate-400">{p.description}</div>{/if}
											</td>
											<td><span class={p.action === 'Allow' ? 'badge badge-success' : p.action === 'Deny' ? 'badge badge-danger' : 'badge badge-info'}>{p.action}</span></td>
											<td>{p.priority}</td>
											<td>{p.enabled ? 'Yes' : 'No'}</td>
											<td>{p.hit_count}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{/if}
				</div>
			</div>

			<!-- Policy Evaluator -->
			<div class="card">
				<div class="card-header">
					<h2 class="card-title">Live Policy Evaluator</h2>
					<Eye class="h-5 w-5 text-slate-400" />
				</div>
				<p class="mb-4 text-sm text-slate-400">Test a request against all active policies. Results come from the real policy engine.</p>
				<form class="space-y-3" on:submit|preventDefault={doEvaluatePolicy}>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<label class="mb-1 block text-xs text-slate-400" for="eval-src-name">Source Service Name</label>
							<input id="eval-src-name" class="input" bind:value={policyEvalForm.source_service_name} placeholder="API Gateway" />
						</div>
						<div>
							<label class="mb-1 block text-xs text-slate-400" for="eval-dst-name">Dest Service Name</label>
							<input id="eval-dst-name" class="input" bind:value={policyEvalForm.dest_service_name} placeholder="Auth Service" />
						</div>
					</div>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<label class="mb-1 block text-xs text-slate-400" for="eval-src">Source SPIFFE ID</label>
							<input id="eval-src" class="input" bind:value={policyEvalForm.source_spiffe_id} placeholder="spiffe://domain/svc-a" />
						</div>
						<div>
							<label class="mb-1 block text-xs text-slate-400" for="eval-dst">Dest SPIFFE ID</label>
							<input id="eval-dst" class="input" bind:value={policyEvalForm.dest_spiffe_id} placeholder="spiffe://domain/svc-b" />
						</div>
					</div>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<label class="mb-1 block text-xs text-slate-400" for="eval-ip">Source IP</label>
							<input id="eval-ip" class="input" bind:value={policyEvalForm.source_ip} placeholder="10.0.0.1" />
						</div>
						<div>
							<label class="mb-1 block text-xs text-slate-400" for="eval-port">Dest Port</label>
							<input id="eval-port" class="input" type="number" bind:value={policyEvalForm.dest_port} placeholder="443" />
						</div>
					</div>
					<div>
						<label class="mb-1 block text-xs text-slate-400" for="eval-trust">Trust Score: {policyEvalForm.trust_score.toFixed(2)}</label>
						<input id="eval-trust" class="w-full" type="range" min="0" max="1" step="0.05" bind:value={policyEvalForm.trust_score} />
					</div>
					<button class="btn btn-primary w-full flex items-center justify-center gap-2" disabled={isEvaluatingPolicy}>
						<Zap class="h-4 w-4" />
						{isEvaluatingPolicy ? 'Evaluating...' : 'Evaluate Against Policies'}
					</button>
				</form>
				{#if policyEvalResult}
					<div class="mt-4 rounded-lg border p-4 {policyEvalResult.action === 'Allow' ? 'border-green-500/40 bg-green-950/30' : policyEvalResult.action === 'Deny' ? 'border-red-500/40 bg-red-950/30' : 'border-slate-600 bg-slate-800/50'}">
						<p class="text-lg font-bold {policyEvalResult.action === 'Allow' ? 'text-green-400' : policyEvalResult.action === 'Deny' ? 'text-red-400' : 'text-slate-200'}">
							→ {policyEvalResult.action}
						</p>
						{#if policyEvalResult.matched_policy_name}
							<p class="mt-1 text-sm text-slate-300">Matched: <span class="font-medium">{policyEvalResult.matched_policy_name}</span></p>
						{:else}
							<p class="mt-1 text-sm text-slate-400">No policy matched — default action applied.</p>
						{/if}
						{#if policyEvalResult.deny_reason}
							<p class="mt-1 text-xs text-red-300">{policyEvalResult.deny_reason}</p>
						{/if}
						<p class="mt-2 text-xs text-slate-500">Evaluated in {policyEvalResult.evaluation_time_us} µs</p>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeSection === 'mesh'}
		<div class="grid grid-cols-1 gap-6 xl:grid-cols-3">
			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Create Tunnel Record</h2>
					<Network class="h-5 w-5 text-slate-400" />
				</div>
				<form class="space-y-4" on:submit|preventDefault={createTunnel}>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="tunnel-service-a">Service A</label>
						<select id="tunnel-service-a" class="input" bind:value={tunnelForm.service_a_id}>
							<option value="">Select service</option>
							{#each services as service}
								<option value={service.id}>{service.name}</option>
							{/each}
						</select>
					</div>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="tunnel-service-b">Service B</label>
						<select id="tunnel-service-b" class="input" bind:value={tunnelForm.service_b_id}>
							<option value="">Select service</option>
							{#each services as service}
								<option value={service.id}>{service.name}</option>
							{/each}
						</select>
					</div>
					<div>
						<label class="mb-1 block text-sm text-slate-400" for="tunnel-endpoint">Endpoint (optional)</label>
						<input id="tunnel-endpoint" class="input" bind:value={tunnelForm.endpoint} placeholder="127.0.0.1:51820" />
					</div>
					<button class="btn btn-primary w-full" disabled={isCreatingTunnel || services.length < 2}>
						{isCreatingTunnel ? 'Creating...' : 'Create Tunnel'}
					</button>
				</form>
			</div>

			<div class="card xl:col-span-2">
				<div class="card-header">
					<h2 class="card-title">Topology Snapshot</h2>
					<span class="text-sm text-slate-400">{topology.nodes.length} nodes / {topology.edges.length} edges</span>
				</div>
				<p class="mb-4 text-sm text-slate-400">
					This view reflects persisted mesh metadata. OS-level WireGuard interface creation is not yet
					started directly by the desktop runtime.
				</p>
				<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
					<div class="rounded-lg bg-slate-700/30 p-4">
						<h3 class="mb-3 text-sm font-semibold text-slate-200">Nodes</h3>
						<div class="space-y-3">
							{#if topology.nodes.length === 0}
								<p class="text-sm text-slate-400">No topology nodes are available.</p>
							{:else}
								{#each topology.nodes as node}
									<div class="flex items-center justify-between">
										<div>
											<p class="text-sm text-slate-100">{node.name}</p>
											<p class="text-xs text-slate-400">Trust {Math.round(node.trust_score * 100)}%</p>
										</div>
										<span class={getStatusBadgeClass(node.status)}>{node.status}</span>
									</div>
								{/each}
							{/if}
						</div>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-4">
						<h3 class="mb-3 text-sm font-semibold text-slate-200">Edges</h3>
						<div class="space-y-3">
							{#if topology.edges.length === 0}
								<p class="text-sm text-slate-400">No topology edges are available.</p>
							{:else}
								{#each topology.edges as edge}
									<div>
										<p class="text-sm text-slate-100">{serviceName(edge.source)} -> {serviceName(edge.target)}</p>
										<p class="text-xs text-slate-400">Status: {edge.status}</p>
									</div>
								{/each}
							{/if}
						</div>
					</div>
				</div>
			</div>
		</div>

		<div class="card">
			<div class="card-header">
				<h2 class="card-title">Tunnel Records</h2>
				<span class="text-sm text-slate-400">{tunnels.length} persisted</span>
			</div>
			{#if tunnels.length === 0}
				<p class="text-sm text-slate-400">No tunnel records exist yet.</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="table">
						<thead>
							<tr>
								<th>Interface</th>
								<th>Pair</th>
								<th>Virtual IP</th>
								<th>Status</th>
								<th>Traffic</th>
								<th>Handshake</th>
							</tr>
						</thead>
						<tbody>
							{#each tunnels as tunnel}
								<tr>
									<td>{tunnel.interface_name}</td>
									<td>{serviceName(tunnel.service_a_id)} / {serviceName(tunnel.service_b_id)}</td>
									<td>{tunnel.virtual_ip}</td>
									<td><span class={getStatusBadgeClass(tunnel.status)}>{tunnel.status}</span></td>
									<td>{formatBytes(tunnel.bytes_sent + tunnel.bytes_received)}</td>
									<td>{formatDate(tunnel.last_handshake)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{:else if activeSection === 'attacks'}
		<div class="grid grid-cols-1 gap-4 md:grid-cols-3">
			<div class="card">
				<p class="text-sm text-slate-400">Recorded Attacks (24h)</p>
				<p class="mt-2 text-2xl font-bold text-slate-100">{attackStats.total_24h}</p>
			</div>
			<div class="card">
				<p class="text-sm text-slate-400">Blocked Attacks</p>
				<p class="mt-2 text-2xl font-bold text-slate-100">{attackStats.blocked_24h}</p>
			</div>
			<div class="card">
				<p class="text-sm text-slate-400">Blacklist Entries</p>
				<p class="mt-2 text-2xl font-bold text-slate-100">{attackStats.blacklist_count}</p>
			</div>
		</div>

		<div class="grid grid-cols-1 gap-4 xl:grid-cols-2">
			<!-- Blacklist IP Form -->
			<div class="card">
				<div class="card-header">
					<h2 class="card-title">Blacklist IP</h2>
					<Ban class="h-5 w-5 text-red-400" />
				</div>
				<form class="space-y-3" on:submit|preventDefault={doBlacklistIp}>
					<div>
						<label class="mb-1 block text-xs text-slate-400" for="bl-ip">IP Address</label>
						<input id="bl-ip" class="input" bind:value={blacklistForm.ip} placeholder="1.2.3.4" />
					</div>
					<div>
						<label class="mb-1 block text-xs text-slate-400" for="bl-reason">Reason</label>
						<input id="bl-reason" class="input" bind:value={blacklistForm.reason} placeholder="Repeated SYN flood" />
					</div>
					<div>
						<label class="mb-1 block text-xs text-slate-400" for="bl-hours">Duration (hours, blank = permanent)</label>
						<input id="bl-hours" class="input" type="number" bind:value={blacklistForm.duration_hours} placeholder="24" />
					</div>
					<button class="btn btn-danger w-full flex items-center justify-center gap-2" disabled={isBlacklistingIp}>
						<Ban class="h-4 w-4" />
						{isBlacklistingIp ? 'Blacklisting...' : 'Blacklist IP'}
					</button>
				</form>
			</div>
			<!-- Recent Alerts with Acknowledge -->
			<div class="card">
				<div class="card-header">
					<h2 class="card-title">Recent Alerts</h2>
					<span class="badge badge-danger">{recentAlerts.filter(a => !a.acknowledged).length} open</span>
				</div>
				<div class="space-y-2">
					{#if recentAlerts.length === 0}
						<p class="text-sm text-slate-400">No alerts recorded yet.</p>
					{:else}
						{#each recentAlerts as alert}
							<div class="flex items-start justify-between gap-3 rounded-lg border border-slate-700 bg-slate-700/30 p-3">
								<div class="min-w-0">
									<p class="text-sm font-medium {getSeverityClass(alert.severity)}">{alert.title}</p>
									<p class="text-xs text-slate-400 mt-0.5">{alert.message}</p>
									<p class="text-xs text-slate-500 mt-1">{formatDate(alert.created_at)}</p>
								</div>
								{#if !alert.acknowledged}
									<button
										class="btn btn-secondary flex items-center gap-1 py-1 px-2 text-xs flex-shrink-0"
										on:click={() => doAcknowledgeAlert(alert.id)}
										disabled={isAcknowledgingAlertId === alert.id}
									>
										<CheckCheck class="h-3 w-3" />
										{isAcknowledgingAlertId === alert.id ? '...' : 'Ack'}
									</button>
								{:else}
									<span class="text-xs text-slate-500 flex-shrink-0">Ack'd</span>
								{/if}
							</div>
						{/each}
					{/if}
				</div>
			</div>
		</div>

		<div class="grid grid-cols-1 gap-6 xl:grid-cols-3">
			<div class="card xl:col-span-2">
				<div class="card-header">
					<h2 class="card-title">Recent Attack Events</h2>
					<span class="text-sm text-slate-400">{recentAttacks.length} rows</span>
				</div>
				{#if recentAttacks.length === 0}
					<p class="text-sm text-slate-400">No recorded attack events are available.</p>
				{:else}
					<div class="overflow-x-auto">
						<table class="table">
							<thead>
								<tr>
									<th>Type</th>
									<th>Source</th>
									<th>Destination</th>
									<th>Severity</th>
									<th>Packets</th>
									<th>Blocked</th>
								</tr>
							</thead>
							<tbody>
								{#each recentAttacks as event}
									<tr>
										<td>{event.attack_type}</td>
										<td>{event.source_ip}</td>
										<td>{event.destination_ip}</td>
										<td class={getSeverityClass(event.severity)}>{event.severity}</td>
										<td>{event.packet_count}</td>
										<td>{event.blocked ? 'Yes' : 'No'}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</div>

			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Top Attackers</h2>
					<span class="text-sm text-slate-400">{attackStats.top_attackers.length} entries</span>
				</div>
				<div class="space-y-3">
					{#if attackStats.top_attackers.length === 0}
						<p class="text-sm text-slate-400">No attacker rankings are available.</p>
					{:else}
						{#each attackStats.top_attackers as [ip, count]}
							<div class="rounded-lg bg-slate-700/30 p-3">
								<p class="text-sm text-slate-100">{ip}</p>
								<p class="text-xs text-slate-400">{count} events</p>
							</div>
						{/each}
					{/if}
				</div>
			</div>
		</div>

		<div class="card">
			<div class="card-header">
				<h2 class="card-title">Blacklist</h2>
				<span class="text-sm text-slate-400">{blacklist.length} entries</span>
			</div>
			{#if blacklist.length === 0}
				<p class="text-sm text-slate-400">No IPs are currently blacklisted.</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="table">
						<thead>
							<tr>
								<th>IP</th>
								<th>Reason</th>
								<th>Expires</th>
								<th>Created</th>
							</tr>
						</thead>
						<tbody>
							{#each blacklist as entry}
								<tr>
									<td>{entry.ip}</td>
									<td>{entry.reason}</td>
									<td>{formatDate(entry.expires_at)}</td>
									<td>{formatDate(entry.created_at)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{:else if activeSection === 'audit'}
		<div class="card">
			<div class="card-header">
				<h2 class="card-title">Audit Log</h2>
				<div class="flex items-center gap-2">
					<select class="input py-1 px-2 text-sm" bind:value={auditFilter} on:change={loadFilteredAudit}>
						<option value="">All events</option>
						<option value="identity">identity</option>
						<option value="policy">policy</option>
						<option value="attestation">attestation</option>
						<option value="attack">attack</option>
						<option value="system">system</option>
					</select>
					<button class="btn btn-secondary flex items-center gap-1 py-1 px-3 text-sm" on:click={doExportLogs} disabled={isExportingLogs}>
						<Download class="h-4 w-4" />
						{isExportingLogs ? 'Exporting...' : 'Export'}
					</button>
					<span class="text-sm text-slate-400">{auditLogs.length} events</span>
				</div>
			</div>
			{#if auditLogs.length === 0}
				<p class="text-sm text-slate-400">No audit records are available yet.</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="table">
						<thead>
							<tr>
								<th>Timestamp</th>
								<th>Event Type</th>
								<th>Action</th>
								<th>Subject</th>
								<th>Success</th>
								<th>Details</th>
							</tr>
						</thead>
						<tbody>
							{#each auditLogs as log}
								<tr>
									<td>{formatDate(log.created_at)}</td>
									<td><span class="badge badge-info">{log.event_type}</span></td>
									<td>{log.action}</td>
									<td>{log.subject ?? 'N/A'}</td>
									<td>{log.success ? '✓' : '✗'}</td>
									<td class="max-w-[360px] truncate text-slate-300">{log.details ?? 'N/A'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{:else if activeSection === 'settings'}
		<div class="grid grid-cols-1 gap-6 xl:grid-cols-3">
			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Runtime Paths</h2>
					<Settings class="h-5 w-5 text-slate-400" />
				</div>
				{#if configData}
					<div class="space-y-3 text-sm text-slate-300">
						<div>
							<p class="text-slate-400">Database</p>
							<p class="break-all">{configData.storage.database_path}</p>
						</div>
						<div>
							<p class="text-slate-400">Log File</p>
							<p class="break-all">{configData.logging.file_path}</p>
						</div>
						<div>
							<p class="text-slate-400">Trust Domain</p>
							<p>{configData.identity.trust_domain}</p>
						</div>
					</div>
				{:else}
					<p class="text-sm text-slate-400">Configuration has not loaded yet.</p>
				{/if}
			</div>

			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Environment Status</h2>
					<Activity class="h-5 w-5 text-slate-400" />
				</div>
				<div class="space-y-3 text-sm text-slate-300">
					<div>
						<p class="text-slate-400">TPM</p>
						<p>{tpmStatus?.available ? 'Available' : 'Unavailable - software fallback in use'}</p>
					</div>
					<div>
						<p class="text-slate-400">eBPF Capture Loop</p>
						<p>Not auto-started by the desktop runtime</p>
					</div>
					<div>
						<p class="text-slate-400">Service Discovery</p>
						<p>Manual service attestation scan is available from the Services page</p>
					</div>
				</div>
			</div>

			<div class="card xl:col-span-1">
				<div class="card-header">
					<h2 class="card-title">Database Stats</h2>
					<FileText class="h-5 w-5 text-slate-400" />
				</div>
				{#if databaseStats}
					<div class="space-y-3 text-sm text-slate-300">
						<p>Services: {databaseStats.service_count}</p>
						<p>Policies: {databaseStats.policy_count}</p>
						<p>Tunnels: {databaseStats.tunnel_count}</p>
						<p>Attacks (24h): {databaseStats.attack_count_24h}</p>
						<p>Open Alerts: {databaseStats.unacknowledged_alerts}</p>
						<p>Blacklist: {databaseStats.blacklist_count}</p>
					</div>
				{:else}
					<p class="text-sm text-slate-400">Database statistics are not available yet.</p>
				{/if}
			</div>
			<!-- Development Tools -->
			<div class="card xl:col-span-1 border-orange-500/30">
				<div class="card-header">
					<h2 class="card-title text-orange-300">Development Tools</h2>
					<AlertTriangle class="h-5 w-5 text-orange-400" />
				</div>
				<p class="mb-4 text-sm text-slate-400">
					<strong class="text-orange-300">Warning:</strong> Loading a demo workspace clears ALL existing data — including any real services you registered.
				</p>
				<button class="btn btn-secondary w-full flex items-center justify-center gap-2" on:click={loadDemoData} disabled={isSeeding}>
					{isSeeding ? 'Loading Demo Workspace...' : 'Load Demo Workspace'}
				</button>
				<p class="mt-2 text-xs text-slate-500">Inserts 3 services (mapped to /usr/bin/env, /bin/sh, /bin/ls), 2 policies, 1 tunnel, 3 attacks, 3 alerts. All data is real — binaries will be scanned for real SHA-256 hashes.</p>
			</div>
		</div>

		{#if configData}
			<div class="card">
				<div class="card-header">
					<h2 class="card-title">Effective Configuration</h2>
					<Lock class="h-5 w-5 text-slate-400" />
				</div>
				<div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
					<div class="rounded-lg bg-slate-700/30 p-4">
						<p class="text-xs uppercase tracking-wide text-slate-400">General</p>
						<p class="mt-2 text-sm text-slate-200">Theme: {configData.general.theme}</p>
						<p class="text-sm text-slate-200">Notifications: {configData.general.notifications_enabled ? 'Enabled' : 'Disabled'}</p>
						<p class="text-sm text-slate-200">Auto-start: {configData.general.autostart ? 'On' : 'Off'}</p>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-4">
						<p class="text-xs uppercase tracking-wide text-slate-400">Policy</p>
						<p class="mt-2 text-sm text-slate-200">Default action: {configData.policy.default_action}</p>
						<p class="text-sm text-slate-200">Cache TTL: {configData.policy.cache_ttl_seconds}s</p>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-4">
						<p class="text-xs uppercase tracking-wide text-slate-400">WireGuard</p>
						<p class="mt-2 text-sm text-slate-200">Subnet: {configData.wireguard.virtual_subnet}</p>
						<p class="text-sm text-slate-200">Port: {configData.wireguard.listen_port}</p>
						<p class="text-sm text-slate-200">MTU: {configData.wireguard.mtu}</p>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-4">
						<p class="text-xs uppercase tracking-wide text-slate-400">eBPF</p>
						<p class="mt-2 text-sm text-slate-200">Enabled: {configData.ebpf.enabled ? 'Yes' : 'No'}</p>
						<p class="text-sm text-slate-200">Interface: {configData.ebpf.interface}</p>
						<p class="text-sm text-slate-200">SYN threshold: {configData.ebpf.syn_flood_threshold}</p>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-4">
						<p class="text-xs uppercase tracking-wide text-slate-400">Attestation</p>
						<p class="mt-2 text-sm text-slate-200">TPM requested: {configData.attestation.tpm_enabled ? 'Yes' : 'No'}</p>
						<p class="text-sm text-slate-200">Full access threshold: {configData.attestation.full_access_threshold}</p>
						<p class="text-sm text-slate-200">Isolation threshold: {configData.attestation.isolation_threshold}</p>
					</div>
					<div class="rounded-lg bg-slate-700/30 p-4">
						<p class="text-xs uppercase tracking-wide text-slate-400">Logging</p>
						<p class="mt-2 text-sm text-slate-200">Level: {configData.logging.level}</p>
						<p class="text-sm text-slate-200">File logging: {configData.logging.file_enabled ? 'Enabled' : 'Disabled'}</p>
						<p class="text-sm text-slate-200">Max size: {configData.logging.max_file_size_mb} MB</p>
					</div>
				</div>
			</div>
		{/if}
	{/if}
</div>
