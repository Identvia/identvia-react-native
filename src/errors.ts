export class IdentviaError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.name = 'IdentviaError'; this.code = code; }
}
export class ConfigurationError extends IdentviaError { constructor(m: string) { super('configuration_error', m); this.name = 'ConfigurationError'; } }
export class InvalidStateError extends IdentviaError { constructor(m: string) { super('invalid_state', m); this.name = 'InvalidStateError'; } }
export class ValidationError extends IdentviaError { constructor(m: string) { super('validation_error', m); this.name = 'ValidationError'; } }
export class UnsupportedError extends IdentviaError { constructor(m: string) { super('unsupported', m); this.name = 'UnsupportedError'; } }
export class CancelledError extends IdentviaError { constructor(m = 'The user closed the sign-in window.') { super('cancelled', m); this.name = 'CancelledError'; } }
export class AuthorizationError extends IdentviaError {
  readonly error: string; readonly errorDescription?: string;
  constructor(error: string, description?: string) { super(error, description ? `${error}: ${description}` : error); this.name = 'AuthorizationError'; this.error = error; this.errorDescription = description; }
}
export class TokenError extends IdentviaError {
  readonly error: string; readonly errorDescription?: string; readonly status: number;
  constructor(error: string, description: string | undefined, status: number) { super(error, description ? `${error}: ${description}` : error); this.name = 'TokenError'; this.error = error; this.errorDescription = description; this.status = status; }
}
