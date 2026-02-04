import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { TenantList } from './pages/tenants/TenantList';
import { TenantCreate } from './pages/tenants/TenantCreate';
import { TenantDetail } from './pages/tenants/TenantDetail';
import { TenantEdit } from './pages/tenants/TenantEdit';
import { ClientList } from './pages/clients/ClientList';
import { ClientCreate } from './pages/clients/ClientCreate';
import { ClientDetail } from './pages/clients/ClientDetail';
import { SigningKeys } from './pages/signing-keys/SigningKeys';
import { TokenList } from './pages/tokens/TokenList';
import { IdentityProviderList } from './pages/identity-providers/IdentityProviderList';
import { IdentityProviderCreate } from './pages/identity-providers/IdentityProviderCreate';
import { IdentityProviderDetail } from './pages/identity-providers/IdentityProviderDetail';
import { Toaster } from './components/ui/toaster';

export function App() {
  return (
    <>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />

          {/* Tenant routes */}
          <Route path="tenants" element={<TenantList />} />
          <Route path="tenants/new" element={<TenantCreate />} />
          <Route path="tenants/:tenantId" element={<TenantDetail />} />
          <Route path="tenants/:tenantId/edit" element={<TenantEdit />} />

          {/* Client routes (nested under tenant) */}
          <Route path="tenants/:tenantId/clients" element={<ClientList />} />
          <Route path="tenants/:tenantId/clients/new" element={<ClientCreate />} />
          <Route path="tenants/:tenantId/clients/:clientId" element={<ClientDetail />} />

          {/* Signing keys route */}
          <Route path="tenants/:tenantId/signing-keys" element={<SigningKeys />} />

          {/* Token management */}
          <Route path="tenants/:tenantId/tokens" element={<TokenList />} />

          {/* Identity providers */}
          <Route path="tenants/:tenantId/identity-providers" element={<IdentityProviderList />} />
          <Route path="tenants/:tenantId/identity-providers/new" element={<IdentityProviderCreate />} />
          <Route path="tenants/:tenantId/identity-providers/:providerId" element={<IdentityProviderDetail />} />
        </Route>
      </Routes>
      <Toaster />
    </>
  );
}
