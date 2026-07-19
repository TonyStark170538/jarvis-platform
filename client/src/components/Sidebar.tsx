import { useLocation } from 'wouter';
import { 
  LayoutDashboard, 
  Zap, 
  Eye, 
  AlertTriangle, 
  Database, 
  BarChart3, 
  Globe, 
  Settings,
  LogOut
} from 'lucide-react';
import { Card } from '@/components/ui/card';

/**
 * J.A.R.V.I.S. Sidebar Navigation
 * Design: Dark sidebar with neon cyan highlights, glassmorphism effect
 */

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/attack-lab', label: 'Attack Lab', icon: Zap },
  { path: '/monitoring', label: 'Monitoring', icon: Eye },
  { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { path: '/assets', label: 'Assets', icon: Database },
  { path: '/reports', label: 'Reports', icon: BarChart3 },
  { path: '/intelligence', label: 'Intelligence', icon: Globe },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const [location, navigate] = useLocation();

  return (
    <div className="w-64 bg-sidebar border-r border-sidebar-border glass flex flex-col">
      {/* Logo Section */}
      <div className="p-6 border-b border-sidebar-border">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center border border-accent/50 shadow-[0_0_15px_rgba(102,200,255,0.3)]">
            <span className="text-white font-mono font-bold text-sm">J</span>
          </div>
          <div>
            <p className="font-mono font-bold text-sm text-foreground">J.A.R.V.I.S.</p>
            <p className="text-xs text-muted-foreground">Command Center</p>
          </div>
        </div>
      </div>

      {/* Navigation Items */}
      <nav className="flex-1 overflow-y-auto px-4 py-6 space-y-2">
        {navItems.map((item) => {
          const isActive = location === item.path;
          const Icon = item.icon;

          return (
            <button
              key={item.path}
              onClick={() => navigate(item.path)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                isActive
                  ? 'bg-accent/20 text-accent border border-accent/50 shadow-[0_0_15px_rgba(102,200,255,0.2)]'
                  : 'text-sidebar-foreground hover:bg-sidebar-accent/10 border border-transparent'
              }`}
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
              <span className="text-sm font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Bottom Section */}
      <div className="p-4 border-t border-sidebar-border space-y-3">
        <Card className="glass p-3 text-xs">
          <p className="text-muted-foreground mb-2">Status</p>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
            <span className="font-mono">Online</span>
          </div>
        </Card>
        
        <button className="w-full flex items-center gap-2 px-4 py-2 rounded-lg text-sidebar-foreground hover:bg-destructive/20 hover:text-destructive transition-all text-sm">
          <LogOut className="w-4 h-4" />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
}
