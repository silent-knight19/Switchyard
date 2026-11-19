export interface ConfigIssue {
  field: string;
  message: string;
}

export class ConfigValidationError extends Error {
  public readonly issues: readonly ConfigIssue[];

  constructor(issues: ConfigIssue[]) {
    const formatted = issues.map((i) => `  - ${i.field}: ${i.message}`).join('\n');
    super(`Configuration validation failed:\n${formatted}`);
    this.name = 'ConfigValidationError';
    this.issues = Object.freeze([...issues]);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
