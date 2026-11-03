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
      DeviceCheck,
      DeviceSshProfile,
      DeviceCompany,
      DeviceCredential,
    ]),
  ],
  controllers: [DevicesController],
  providers: [DevicesService],
})
export class DevicesModule {}
