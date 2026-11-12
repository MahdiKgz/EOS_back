import { DeviceActionSecret } from "./device-secret.entity";
import { DeviceSecretsService } from "./device-secrets.service";
import { DeviceSecretsController } from "./device-secrets.controller";
import { DeviceActionsService } from "./device-actions.service";
import { DeviceActionsController } from "./device-actions.controller";
import { CiscoAccessService } from "./cisco-access.service";
import { CiscoAccessController } from "./cisco-access.controller";
import { DeviceCiscoAccess, CiscoEnableCredential } from "./cisco-access.entity";
import { DeviceCapabilitiesController } from "./device-capabilities.controller";
import { DeviceCapabilitiesService } from "./device-capabilities.service";
import { DeviceCapabilityCache } from "./device-capability.entity";
import { VendorCatalogController } from "./vendor-catalog.controller";
import { VendorCatalogService } from "./vendor-catalog.service";
import { DeviceMonitoringController } from "./device-monitoring.controller";
import { DeviceMonitoringService } from "./device-monitoring.service";
import { DeviceMonitoringWorker } from "./device-monitoring.worker";
import { DeviceMonitoring } from "./device-monitoring.entity";
import { VendorApiCredentialsService } from "./vendor-api-credentials.service";
import { DeviceApiCredential } from "./vendor-api-credential.entity";
import { VendorApiController } from "./vendor-api.controller";
import { DeviceChannelsService } from "./device-channels.service";
import { DeviceChannelsController } from "./device-channels.controller";
import { DeviceSecondaryChannel, DeviceSnmpCredential } from "./device-channels.entity";
import { DeviceBackupsService } from "./device-backups.service";
import { DeviceRestoresService } from "./device-restores.service";
import { BackupActivityService } from "./backup-activity.service";
import { DeviceTerminalService } from "./device-terminal.service";
import { DeviceTerminalController } from "./device-terminal.controller";
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { DeviceCheck } from "./device-check.entity";
import { DeviceSshProfile } from "./device-ssh-profile.entity";
import { DeviceCompany, DeviceCredential } from "./device-onboarding.entity";
import { Device } from "./device.entity";
import { DevicesController } from "./devices.controller";
import { DevicesService } from "./devices.service";
@Module({
  imports: [
    TypeOrmModule.forFeature([
      Device,
      DeviceActionSecret,
      DeviceCheck,
      DeviceSshProfile,
      DeviceCompany,
      DeviceCredential,
      DeviceApiCredential,
      DeviceMonitoring,
      DeviceCapabilityCache,
      DeviceCiscoAccess,
      CiscoEnableCredential,
      DeviceSecondaryChannel,
      DeviceSnmpCredential,
    ]),
  ],
  controllers: [
    DeviceSecretsController,
    DeviceActionsController,
    CiscoAccessController,
    DeviceCapabilitiesController,
    VendorCatalogController,
    DeviceMonitoringController,
    VendorApiController,
    DeviceChannelsController,
    DevicesController,
    DeviceTerminalController,
  ],
  providers: [
    DeviceSecretsService,
    DeviceActionsService,
    CiscoAccessService,
    DeviceCapabilitiesService,
    VendorCatalogService,
    DeviceMonitoringService,
    DeviceMonitoringWorker,
    DevicesService,
    VendorApiCredentialsService,
    DeviceChannelsService,
    DeviceBackupsService,
    DeviceRestoresService,
    BackupActivityService,
    DeviceTerminalService,
  ],
})
export class DevicesModule {}
