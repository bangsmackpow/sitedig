import { z } from 'zod';

export const portScopeSchema = z.enum(['common', 'top100', 'top1000']);
export const scanProfileSchema = z.enum(['quick', 'standard', 'deep', 'custom']);
export const toolNameSchema = z.enum([
  'nmap',
  'whatweb',
  'wpscan',
  'http',
  'tls',
  'subfinder',
  'dnsx',
  'rdap',
  'email',
  'nuclei',
  'httpx',
  'retire',
  'testssl',
  'feroxbuster',
  'waybackurls',
  'osv',
  'crawl-rules',
  'security-txt',
  'page-recon',
  'header-posture',
  'dns-hardening',
  'dnssec',
  'ip-intel',
]);
export const baseToolNameSchema = z.enum(['nmap', 'whatweb', 'wpscan', 'http', 'tls']);
export const moduleIdSchema = z.enum([
  'asset-discovery',
  'vuln-scan',
  'tls-hardening',
  'content-discovery',
  'cve-context',
  'remediation-playbook',
  'web-trust',
  'domain-hardening',
  'infra-intel',
]);

export const customOptionsSchema = z
  .object({
    portScope: portScopeSchema,
    enabledTools: z.array(baseToolNameSchema).min(1),
    path: z.string().max(2048).default('/'),
    followRedirects: z.boolean().default(true),
    userAgent: z.string().max(512).optional(),
    timeoutMs: z.number().int().min(60_000).max(300_000).optional(),
  })
  .strict();

export const createJobSchema = z
  .object({
    target: z.string().min(1).max(2048),
    profile: scanProfileSchema,
    consent: z.literal(true, { errorMap: () => ({ message: 'Authorization acknowledgement is required.' }) }),
    custom: customOptionsSchema.optional(),
    modules: z.array(moduleIdSchema).max(9).optional(),
  })
  .strict();

const scheduleFrequencySchema = z.enum(['daily', 'weekly']);
const scheduleAlertThresholdSchema = z.enum(['off', 'high', 'medium', 'all']);

export const createScheduleSchema = z
  .object({
    target: z.string().min(1).max(2048),
    profile: scanProfileSchema,
    custom: customOptionsSchema.optional(),
    modules: z.array(moduleIdSchema).max(9).optional(),
    frequency: scheduleFrequencySchema,
    hourUtc: z.number().int().min(0).max(23),
    minuteUtc: z.number().int().min(0).max(59).default(0),
    dayOfWeek: z.number().int().min(0).max(6).optional(),
    alertMinSeverity: scheduleAlertThresholdSchema.default('high'),
    alertOnFailure: z.boolean().default(true),
    consent: z.literal(true, { errorMap: () => ({ message: 'Recurring authorization acknowledgement is required.' }) }),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.frequency === 'weekly' && value.dayOfWeek === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['dayOfWeek'], message: 'Choose a day of the week for weekly schedules.' });
    }
  });

export const updateScheduleSchema = z
  .object({
    frequency: scheduleFrequencySchema.optional(),
    hourUtc: z.number().int().min(0).max(23).optional(),
    minuteUtc: z.number().int().min(0).max(59).optional(),
    dayOfWeek: z.number().int().min(0).max(6).nullable().optional(),
    alertMinSeverity: scheduleAlertThresholdSchema.optional(),
    alertOnFailure: z.boolean().optional(),
    enabled: z.boolean().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.frequency === 'weekly' && value.dayOfWeek == null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['dayOfWeek'], message: 'Choose a day of the week for weekly schedules.' });
    }
  });

export type CreateJobInput = z.infer<typeof createJobSchema>;
export type CustomOptionsInput = z.infer<typeof customOptionsSchema>;
export type ModuleInput = z.infer<typeof moduleIdSchema>;
export type CreateScheduleInput = z.infer<typeof createScheduleSchema>;
export type UpdateScheduleInput = z.infer<typeof updateScheduleSchema>;
