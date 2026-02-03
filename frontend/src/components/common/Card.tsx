import { clsx } from 'clsx';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
}

export function Card({ children, className, title }: CardProps) {
  return (
    <div className={clsx('rounded-lg border border-gray-800 bg-gray-900', className)}>
      {title && (
        <div className="border-b border-gray-800 px-4 py-3">
          <h3 className="text-sm font-medium text-gray-200">{title}</h3>
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: number | string;
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

export function StatCard({ label, value, variant = 'default' }: StatCardProps) {
  const valueColor = {
    default: 'text-white',
    danger: 'text-red-400',
    warning: 'text-yellow-400',
    success: 'text-green-400',
  }[variant];

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <div className="text-xs text-gray-400 uppercase tracking-wider">{label}</div>
      <div className={clsx('mt-1 text-2xl font-bold', valueColor)}>{value}</div>
    </div>
  );
}
