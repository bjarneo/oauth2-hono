import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { Plus, Trash2, Star, RefreshCw, Key } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import {
  listSigningKeys,
  createSigningKey,
  setSigningKeyPrimary,
  deleteSigningKey,
  rotateSigningKeys,
} from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { SigningKey } from '@oauth2-hono/shared';

const ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'] as const;

export function SigningKeys() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const queryClient = useQueryClient();
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [rotateDialogOpen, setRotateDialogOpen] = useState(false);
  const [keyToDelete, setKeyToDelete] = useState<SigningKey | null>(null);
  const [newKeyAlgorithm, setNewKeyAlgorithm] = useState<string>('RS256');

  const { data: keys, isLoading } = useQuery({
    queryKey: ['signing-keys', tenantId],
    queryFn: () => listSigningKeys(tenantId!),
    enabled: Boolean(tenantId),
  });

  const createMutation = useMutation({
    mutationFn: (algorithm: string) =>
      createSigningKey(tenantId!, { algorithm, isPrimary: !keys?.length }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['signing-keys', tenantId] });
      toast({ title: 'Key created', description: 'New signing key has been created.' });
      setCreateDialogOpen(false);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create key',
      });
    },
  });

  const setPrimaryMutation = useMutation({
    mutationFn: setSigningKeyPrimary,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['signing-keys', tenantId] });
      toast({ title: 'Primary key updated', description: 'The primary signing key has been changed.' });
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to set primary key',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteSigningKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['signing-keys', tenantId] });
      toast({ title: 'Key deleted', description: 'The signing key has been deleted.' });
      setDeleteDialogOpen(false);
      setKeyToDelete(null);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete key',
      });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: () => rotateSigningKeys(tenantId!),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['signing-keys', tenantId] });
      toast({
        title: 'Keys rotated',
        description: `New key ${result.newKey.kid} is now primary.`,
      });
      setRotateDialogOpen(false);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to rotate keys',
      });
    },
  });

  const handleDelete = (key: SigningKey) => {
    setKeyToDelete(key);
    setDeleteDialogOpen(true);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Signing Keys</h1>
          <p className="text-muted-foreground">Manage JWT signing keys for this tenant</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setRotateDialogOpen(true)}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Rotate Keys
          </Button>
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            New Key
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Signing Keys</CardTitle>
          <CardDescription>
            Keys used to sign JWTs. The primary key is used for new tokens.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="text-muted-foreground">Loading...</div>
            </div>
          ) : !keys?.length ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Key className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-muted-foreground mb-4">No signing keys configured</p>
              <Button onClick={() => setCreateDialogOpen(true)}>Create first key</Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Key ID (kid)</TableHead>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="w-[150px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-mono text-sm">{key.kid}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{key.algorithm}</Badge>
                    </TableCell>
                    <TableCell>
                      {key.isPrimary ? (
                        <Badge variant="success">
                          <Star className="h-3 w-3 mr-1" />
                          Primary
                        </Badge>
                      ) : (
                        <Badge variant="secondary">Backup</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(key.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {key.expiresAt ? new Date(key.expiresAt).toLocaleDateString() : 'Never'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        {!key.isPrimary && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setPrimaryMutation.mutate(key.id)}
                          >
                            <Star className="h-4 w-4 mr-1" />
                            Set Primary
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          onClick={() => handleDelete(key)}
                          disabled={key.isPrimary && keys.length > 1}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create Key Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Signing Key</DialogTitle>
            <DialogDescription>Create a new JWT signing key pair.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Algorithm</Label>
              <Select value={newKeyAlgorithm} onValueChange={setNewKeyAlgorithm}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ALGORITHMS.map((alg) => (
                    <SelectItem key={alg} value={alg}>
                      {alg}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                RS256 is recommended for most use cases
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMutation.mutate(newKeyAlgorithm)}>
              {createMutation.isPending ? 'Creating...' : 'Create Key'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Key Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Signing Key</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete key "{keyToDelete?.kid}"? Tokens signed with this
              key will no longer be verifiable.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => keyToDelete && deleteMutation.mutate(keyToDelete.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Rotate Keys Dialog */}
      <AlertDialog open={rotateDialogOpen} onOpenChange={setRotateDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Rotate Signing Keys</AlertDialogTitle>
            <AlertDialogDescription>
              This will create a new primary key with the same algorithm as the current primary.
              The old primary key will be kept as a backup for token verification.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => rotateMutation.mutate()}>
              {rotateMutation.isPending ? 'Rotating...' : 'Rotate Keys'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
