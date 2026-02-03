import { clsx } from 'clsx';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
}

const styles = {
  default: 'bg-gray-800 text-gray-300',
  success: 'bg-green-900/50 text-green-400',
  warning: 'bg-yellow-900/50 text-yellow-400',
  danger: 'bg-red-900/50 text-red-400',
  info: 'bg-blue-900/50 text-blue-400',
};

export function Badge({ children, variant = 'default' }: BadgeProps) {
  return (
    <span className={clsx('inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium', styles[variant])}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const variant = {
    critical: 'danger' as const,
    high: 'danger' as const,
    medium: 'warning' as const,
    low: 'default' as const,
  }[severity] || 'default' as const;

  return <Badge variant={variant}>{severity}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  const variant = {
    active: 'success' as const,
    running: 'info' as const,
    completed: 'success' as const,
    pending: 'warning' as const,
    failed: 'danger' as const,
    error: 'danger' as const,
    stopped: 'default' as const,
    paused: 'warning' as const,
    cancelled: 'default' as const,
  }[status] || 'default' as const;

  return <Badge variant={variant}>{status}</Badge>;
}
