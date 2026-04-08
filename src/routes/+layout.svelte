<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { 
		Shield, 
		Network, 
		AlertTriangle, 
		Settings, 
		Activity,
		FileText,
		Server,
		Lock
	} from 'lucide-svelte';
	
	let currentPage = 'dashboard';
	
	const navItems = [
		{ id: 'dashboard', label: 'Dashboard', icon: Activity },
		{ id: 'services', label: 'Services', icon: Server },
		{ id: 'policies', label: 'Policies', icon: Lock },
		{ id: 'mesh', label: 'Mesh', icon: Network },
		{ id: 'attacks', label: 'Attacks', icon: AlertTriangle },
		{ id: 'audit', label: 'Audit', icon: FileText },
		{ id: 'settings', label: 'Settings', icon: Settings },
	];
</script>

<div class="flex h-screen bg-slate-900">
	<!-- Sidebar -->
	<aside class="w-64 bg-slate-800 border-r border-slate-700 flex flex-col">
		<!-- Logo -->
		<div class="p-4 border-b border-slate-700">
			<div class="flex items-center gap-3">
				<Shield class="w-8 h-8 text-blue-500" />
				<div>
					<h1 class="text-lg font-bold text-slate-100">ZeroTrust Mesh</h1>
					<p class="text-xs text-slate-400">v0.1.0</p>
				</div>
			</div>
		</div>
		
		<!-- Navigation -->
		<nav class="flex-1 p-4">
			<ul class="space-y-1">
				{#each navItems as item}
					<li>
						<button
							on:click={() => currentPage = item.id}
							class="w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors {currentPage === item.id ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-700'}"
						>
							<svelte:component this={item.icon} class="w-5 h-5" />
							<span>{item.label}</span>
						</button>
					</li>
				{/each}
			</ul>
		</nav>
		
		<!-- Status -->
		<div class="p-4 border-t border-slate-700">
			<div class="flex items-center gap-2">
				<div class="w-2 h-2 rounded-full bg-green-500"></div>
				<span class="text-sm text-slate-400">System Healthy</span>
			</div>
		</div>
	</aside>
	
	<!-- Main content -->
	<main class="flex-1 overflow-auto">
		<slot />
	</main>
</div>
