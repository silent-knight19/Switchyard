export type LifecycleState = 'starting' | 'ready' | 'draining' | 'stopped';

export class LifecycleCoordinator {
  private state: LifecycleState = 'starting';

  public getState(): LifecycleState {
    return this.state;
  }

  public setReady(): void {
    if (this.state === 'starting') {
      this.state = 'ready';
    }
  }

  public setDraining(): void {
    this.state = 'draining';
  }

  public setStopped(): void {
    this.state = 'stopped';
  }

  public isReady(): boolean {
    return this.state === 'ready';
  }

  public isShuttingDown(): boolean {
    return this.state === 'draining' || this.state === 'stopped';
  }
}
