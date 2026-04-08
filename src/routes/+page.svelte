<script lang="ts">
	import { onMount } from 'svelte';
	import { 
		Shield, 
		Server, 
		AlertTriangle, 
		Activity,
		Network,
		TrendingUp,
		TrendingDown,
		Lock,
		Unlock
	} from 'lucide-svelte';
	
	// Dashboard data (would be fetched from Tauri backend)
	let dashboardData = {
		services: { total: 0, active: 0, healthy: 0, warning: 0, critical: 0 },
		attacks: { total_24h: 0, blocked_24h: 0, top_types: [] as [string, number][] },
		policies: { total: 0, enabled: 0, recent_hits: 0 },
		alerts: { total: 0, unacknowledged: 0, critical: 0, high: 0 },
		tunnels: { total: 0, active: 0, bytes_transferred: 0 }
	};
	
	let recentAlerts: Array<{
		id: number;
		severity: string;
		title: string;
		message: string;
		created_at: string;
	}> = [];
	
	let services: Array<{
		id: string;
		name: string;
		trust_score: number;
		status: string;
	}> = [];
	
	onMount(async () => {
		// In production, would call Tauri invoke
		// const data = await invoke('get_dashboard_data');
		// dashboardData = data;
		
		// Mock data for development
		dashboardData = {
			services: { total: 12, active: 10, healthy: 8, warning: 2, critical: 0 },
			attacks: { 
				total_24h: 1547, 
				blocked_24h: 1523, 
				top_types: [
					['SYN Flood', 823],
					['Port Scan', 412],
					['HTTP Flood', 189],
					['ICMP Flood', 123]
				] 
			},
			policies: { total: 45, enabled: 42, recent_hits: 15234 },
			alerts: { total: 156, unacknowledged: 12, critical: 2, high: 5 },
			tunnels: { total: 15, active: 14, bytes_transferred: 1234567890 }
		};
		
		services = [
			{ id: '1', name: 'API Gateway', trust_score: 0.95, status: 'active' },
			{ id: '2', name: 'Auth Service', trust_score: 0.88, status: 'active' },
			{ id: '3', name: 'Database', trust_score: 0.72, status: 'active' },
			{ id: '4', name: 'Cache', trust_score: 0.91, status: 'active' },
			{ id: '5', name: 'Worker', trust_score: 0.85, status: 'active' },
		];
		
		recentAlerts = [
			{ id: 1, severity: 'Critical', title: 'SYN Flood Detected', message: 'From 45.123.45.67', created_at: '2 min ago' },
			{ id: 2, severity: 'High', title: 'Port Scan Detected', message: '50+ ports scanned', created_at: '5 min ago' },
			{ id: 3, severity: 'Medium', title: 'Trust Score Drop', message: 'Database service', created_at: '12 min ago' },
			{ id: 4, severity: 'Low', title: 'Policy Updated', message: 'Rate limit changed', created_at: '1 hour ago' },
		];
	});
	
	function getTrustColor(score: number): string {
		if (score >= 0.8) return 'bg-green-500';
		if (score >= 0.5) return 'bg-yellow-500';
		if (score >= 0.3) return 'bg-orange-500';
		return 'bg-red-500';
	}
	
	function getSeverityClass(severity: string): string {
		switch (severity) {
			case 'Critical': return 'text-red-400 bg-red-900/30';
			case 'High': return 'text-orange-400 bg-orange-900/30';
			case 'Medium': return 'text-yellow-400 bg-yellow-900/30';
			case 'Low': return 'text-green-400 bg-green-900/30';
			default: return 'text-blue-400 bg-blue-900/30';
		}
	}
	
	function formatBytes(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
	}
</script>

<div class="p-6 space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-slate-100">Dashboard</h1>
			<p class="text-slate-400">Zero-Trust Network Security Overview</p>
		</div>
		<div class="flex items-center gap-4">
			<button class="btn btn-primary flex items-center gap-2">
				<Activity class="w-4 h-4" />
				Run Scan
			</button>
		</div>
	</div>
	
	<!-- Stats Cards -->
	<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
		<!-- Services Card -->
		<div class="card">
			<div class="flex items-center justify-between">
				<div>
					<p class="text-sm text-slate-400">Active Services</p>
					<p class="text-2xl font-bold text-slate-100">{dashboardData.services.active}</p>
				</div>
				<div class="p-3 bg-blue-900/30 rounded-lg">
					<Server class="w-6 h-6 text-blue-400" />
				</div>
			</div>
			<div class="mt-4 flex items-center gap-4 text-sm">
				<span class="flex items-center gap-1 text-green-400">
					<div class="w-2 h-2 rounded-full bg-green-500"></div>
					{dashboardData.services.healthy} Healthy
				</span>
				<span class="flex items-center gap-1 text-yellow-400">
					<div class="w-2 h-2 rounded-full bg-yellow-500"></div>
					{dashboardData.services.warning} Warning
				</span>
			</div>
		</div>
		
		<!-- Attacks Card -->
		<div class="card">
			<div class="flex items-center justify-between">
				<div>
					<p class="text-sm text-slate-400">Attacks (24h)</p>
					<p class="text-2xl font-bold text-slate-100">{dashboardData.attacks.total_24h.toLocaleString()}</p>
				</div>
				<div class="p-3 bg-red-900/30 rounded-lg">
					<AlertTriangle class="w-6 h-6 text-red-400" />
				</div>
			</div>
			<div class="mt-4 flex items-center gap-2 text-sm">
				<Shield class="w-4 h-4 text-green-400" />
				<span class="text-green-400">{dashboardData.attacks.blocked_24h.toLocaleString()} blocked</span>
				<span class="text-slate-500">
					({Math.round((dashboardData.attacks.blocked_24h / dashboardData.attacks.total_24h) * 100)}%)
				</span>
			</div>
		</div>
		
		<!-- Policies Card -->
		<div class="card">
			<div class="flex items-center justify-between">
				<div>
					<p class="text-sm text-slate-400">Active Policies</p>
					<p class="text-2xl font-bold text-slate-100">{dashboardData.policies.enabled}</p>
				</div>
				<div class="p-3 bg-purple-900/30 rounded-lg">
					<Lock class="w-6 h-6 text-purple-400" />
				</div>
			</div>
			<div class="mt-4 text-sm text-slate-400">
				{dashboardData.policies.recent_hits.toLocaleString()} policy hits
			</div>
		</div>
		
		<!-- Tunnels Card -->
		<div class="card">
			<div class="flex items-center justify-between">
				<div>
					<p class="text-sm text-slate-400">WireGuard Tunnels</p>
					<p class="text-2xl font-bold text-slate-100">{dashboardData.tunnels.active}</p>
				</div>
				<div class="p-3 bg-cyan-900/30 rounded-lg">
					<Network class="w-6 h-6 text-cyan-400" />
				</div>
			</div>
			<div class="mt-4 text-sm text-slate-400">
				{formatBytes(dashboardData.tunnels.bytes_transferred)} transferred
			</div>
		</div>
	</div>
	
	<!-- Main Content Grid -->
	<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
		<!-- Services List -->
		<div class="card lg:col-span-1">
			<div class="card-header">
				<h2 class="card-title">Services</h2>
				<span class="text-sm text-slate-400">{services.length} total</span>
			</div>
			<div class="space-y-3">
				{#each services as service}
					<div class="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
						<div class="flex items-center gap-3">
							<div class="w-2 h-2 rounded-full {getTrustColor(service.trust_score)}"></div>
							<div>
								<p class="font-medium text-slate-100">{service.name}</p>
								<p class="text-xs text-slate-400">Trust: {(service.trust_score * 100).toFixed(0)}%</p>
							</div>
						</div>
						<div class="text-right">
							<span class="badge badge-success">{service.status}</span>
						</div>
					</div>
				{/each}
			</div>
		</div>
		
		<!-- Attack Types Chart -->
		<div class="card lg:col-span-1">
			<div class="card-header">
				<h2 class="card-title">Attack Types (24h)</h2>
			</div>
			<div class="space-y-4">
				{#each dashboardData.attacks.top_types as [type, count]}
					{@const percentage = (count / dashboardData.attacks.total_24h) * 100}
					<div>
						<div class="flex justify-between text-sm mb-1">
							<span class="text-slate-300">{type}</span>
							<span class="text-slate-400">{count.toLocaleString()}</span>
						</div>
						<div class="h-2 bg-slate-700 rounded-full overflow-hidden">
							<div 
								class="h-full bg-red-500 rounded-full transition-all duration-500"
								style="width: {percentage}%"
							></div>
						</div>
					</div>
				{/each}
			</div>
		</div>
		
		<!-- Alerts Feed -->
		<div class="card lg:col-span-1">
			<div class="card-header">
				<h2 class="card-title">Recent Alerts</h2>
				<span class="badge badge-danger">{dashboardData.alerts.unacknowledged} new</span>
			</div>
			<div class="space-y-3">
				{#each recentAlerts as alert}
					<div class="p-3 bg-slate-700/30 rounded-lg border-l-4 {alert.severity === 'Critical' ? 'border-red-500' : alert.severity === 'High' ? 'border-orange-500' : alert.severity === 'Medium' ? 'border-yellow-500' : 'border-green-500'}">
						<div class="flex items-center justify-between mb-1">
							<span class="text-sm font-medium {getSeverityClass(alert.severity).split(' ')[0]}">{alert.title}</span>
							<span class="text-xs text-slate-500">{alert.created_at}</span>
						</div>
						<p class="text-xs text-slate-400">{alert.message}</p>
					</div>
				{/each}
			</div>
		</div>
	</div>
</div>
