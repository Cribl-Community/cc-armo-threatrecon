import type { ReactNode } from 'react';
import { Modal, Text } from '@capra/core';
import { AttentionSolid, CircleCheckFilled, CircleExclamation, CircleXFilled, QuestionCircleOutlined, Reload } from '@capra/icons';
import type { ProviderStatus } from '../core/types';

export type Tone = 'danger' | 'warning' | 'success' | 'info' | 'highlight' | 'neutral' | 'brand';

export function Pill({ tone = 'neutral', children, title }: { tone?: Tone | 'demo'; children: ReactNode; title?: string }) {
  return (
    <span className={`pill pill--${tone}`} title={title}>
      {children}
    </span>
  );
}

export function DemoBadge() {
  return (
    <Pill tone="demo" title="Synthetic data generated in demo mode. Not real telemetry.">
      DEMO DATA
    </Pill>
  );
}

/** Icon + text so status never depends on color alone. */
export function StatusIcon({ tone, size = 'sm' }: { tone: Tone; size?: 'xs' | 'sm' | 'md' }) {
  const cls = `tone-${tone === 'brand' ? 'info' : tone}`;
  const Icon = tone === 'danger' ? CircleXFilled : tone === 'warning' ? AttentionSolid : tone === 'success' ? CircleCheckFilled : tone === 'neutral' ? QuestionCircleOutlined : CircleExclamation;
  return (
    <span className={cls} aria-hidden style={{ display: 'inline-flex' }}>
      <Icon size={size} />
    </span>
  );
}

export function Running({ label }: { label: string }) {
  return (
    <span className="row muted" role="status">
      <span className="spin">
        <Reload size="xs" />
      </span>
      <Text variant="body-sm-normal">{label}</Text>
    </span>
  );
}

export const STATUS_TEXT: Record<ProviderStatus, string> = {
  idle: 'Not run',
  skipped: 'Not checked',
  running: 'Running',
  complete: 'Complete',
  unavailable: 'Unavailable',
  error: 'Error',
};

export function SectionTitle({ icon, children, extra }: { icon?: ReactNode; children: ReactNode; extra?: ReactNode }) {
  return (
    <div className="panel__head">
      <div className="panel__title">
        {icon}
        <Text as="h2" variant="heading-sm">
          {children}
        </Text>
        {extra}
      </div>
    </div>
  );
}

export const fmtInt = (n: number) => n.toLocaleString();

/** Destructive-action confirmation that names exactly what is affected (AGENTS.md rule). */
export function ConfirmDestructive({ open, title, body, confirmText, onConfirm, onCancel }: { open: boolean; title: string; body: string; confirmText: string; onConfirm: () => void | Promise<void>; onCancel: () => void }) {
  return (
    <Modal isOpen={open} onIsOpenChange={(o) => !o && onCancel()} title={title} confirmButtonText={confirmText} cancelButtonText="Cancel" onConfirm={() => void onConfirm()} onClose={onCancel} size="sm">
      <Text as="p" variant="body-md-normal">
        {body}
      </Text>
    </Modal>
  );
}
