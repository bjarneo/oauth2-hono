import { Link, Outlet, useLocation, useParams } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  LayoutDashboard,
  Building2,
  KeyRound,
  Users,
  Key,
  Coins,
  Link2,
  ChevronRight,
  BookOpen,
} from 'lucide-react';

const mainNav = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Tenants', href: '/tenants', icon: Building2 },
  { name: 'Help', href: '/help', icon: BookOpen },
];

const tenantNav = [
  { name: 'Overview', href: '', icon: Building2 },
  { name: 'Clients', href: '/clients', icon: Users },
  { name: 'Signing Keys', href: '/signing-keys', icon: Key },
  { name: 'Tokens', href: '/tokens', icon: Coins },
  { name: 'Identity Providers', href: '/identity-providers', icon: Link2 },
];

export function Layout() {
  const location = useLocation();
  const { tenantId } = useParams();

  const isInTenant = Boolean(tenantId);

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-64 border-r bg-muted/30">
        <div className="flex h-16 items-center border-b px-6">
          <Link to="/dashboard" className="flex items-center gap-2 font-semibold">
            <KeyRound className="h-6 w-6" />
            <span>OAuth2 Admin</span>
          </Link>
        </div>
        <ScrollArea className="h-[calc(100vh-4rem)]">
          <nav className="space-y-1 p-4">
            {mainNav.map((item) => {
              const isActive =
                location.pathname === item.href || (item.href !== '/dashboard' && location.pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  <item.icon className="h-4 w-4" />
                  {item.name}
                </Link>
              );
            })}

            {isInTenant && (
              <>
                <Separator className="my-4" />
                <div className="px-3 py-2 text-xs font-semibold uppercase text-muted-foreground">
                  Tenant Management
                </div>
                {tenantNav.map((item) => {
                  const href = `/tenants/${tenantId}${item.href}`;
                  const isActive = item.href === ''
                    ? location.pathname === `/tenants/${tenantId}`
                    : location.pathname.startsWith(href);
                  return (
                    <Link
                      key={item.href}
                      to={href}
                      className={cn(
                        'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-primary text-primary-foreground'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                      )}
                    >
                      <item.icon className="h-4 w-4" />
                      {item.name}
                    </Link>
                  );
                })}
              </>
            )}
          </nav>
        </ScrollArea>
      </aside>

      {/* Main content */}
      <main className="flex-1">
        <div className="h-16 border-b bg-background px-6 flex items-center">
          <Breadcrumbs />
        </div>
        <div className="p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

function Breadcrumbs() {
  const location = useLocation();
  const parts = location.pathname.split('/').filter(Boolean);

  const breadcrumbs: { name: string; href: string }[] = [];
  let path = '';

  for (const part of parts) {
    path += `/${part}`;

    if (part === 'dashboard') {
      breadcrumbs.push({ name: 'Dashboard', href: path });
    } else if (part === 'help') {
      breadcrumbs.push({ name: 'Help', href: path });
    } else if (part === 'tenants') {
      breadcrumbs.push({ name: 'Tenants', href: path });
    } else if (part === 'clients') {
      breadcrumbs.push({ name: 'Clients', href: path });
    } else if (part === 'signing-keys') {
      breadcrumbs.push({ name: 'Signing Keys', href: path });
    } else if (part === 'tokens') {
      breadcrumbs.push({ name: 'Tokens', href: path });
    } else if (part === 'identity-providers') {
      breadcrumbs.push({ name: 'Identity Providers', href: path });
    } else if (part === 'new') {
      breadcrumbs.push({ name: 'New', href: path });
    } else if (part === 'edit') {
      breadcrumbs.push({ name: 'Edit', href: path });
    } else {
      // Assume it's an ID
      breadcrumbs.push({ name: part.substring(0, 8) + '...', href: path });
    }
  }

  return (
    <nav className="flex items-center gap-1 text-sm text-muted-foreground">
      {breadcrumbs.map((crumb, index) => (
        <div key={crumb.href} className="flex items-center gap-1">
          {index > 0 && <ChevronRight className="h-4 w-4" />}
          {index === breadcrumbs.length - 1 ? (
            <span className="font-medium text-foreground">{crumb.name}</span>
          ) : (
            <Link to={crumb.href} className="hover:text-foreground">
              {crumb.name}
            </Link>
          )}
        </div>
      ))}
    </nav>
  );
}
