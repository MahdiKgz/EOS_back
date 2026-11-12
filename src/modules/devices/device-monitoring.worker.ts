import { Injectable, type OnModuleDestroy } from "@nestjs/common";
import { DeviceMonitoringService } from "./device-monitoring.service";
@Injectable()
export class DeviceMonitoringWorker implements OnModuleDestroy {
  private timer?: NodeJS.Timeout;
  private pending?: Promise<void>;
  constructor(private readonly monitoring: DeviceMonitoringService) {}
  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.tick();
    }, 5000);
    this.timer.unref();
  }
  tick(): Promise<void> {
    if (this.pending) return this.pending;
    this.pending = this.monitoring
      .tick()
      .catch(() => {
        /* Retry after a temporary database failure. */
      })
      .finally(() => {
        this.pending = undefined;
      });
    return this.pending;
  }
  async onModuleDestroy() {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.pending;
  }
}
