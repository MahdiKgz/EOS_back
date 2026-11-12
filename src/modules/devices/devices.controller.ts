import { ParseUUIDPipe } from "@nestjs/common";
import { DeviceBackupsService } from "./device-backups.service";
import { DeviceRestoresService } from "./device-restores.service";
import { BackupActivityService } from "./backup-activity.service";
import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  Param,
  Post,
  Put,
  Query,
  Req,
} from "@nestjs/common";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import {
  AssetsOverviewQueryDto,
  BackupCatalogQueryDto,
  BackupActivityQueryDto,
  BackupActivitySelectionDto,
  PreviewDeviceRestoreDto,
  ExecuteDeviceRestoreDto,
  BackupHistoryQueryDto,
  BackupHistorySelectionDto,
  ClearBackupHistoryDto,
  CompanyNameDto,
  CreateDeviceDto,
  DiscoverRecordersDto,
  SaveCredentialDto,
  DraftConnectionDto,
  ListDevicesDto,
  RegistrationDraftDto,
  RecorderSnapshotDto,
  VerifyRecorderDto,
  SaveDeviceDto,
} from "./device.dto";
import { LinuxSshDto } from "./linux-ssh";
import { DevicesService } from "./devices.service";
@Controller("devices")
export class DevicesController {
  constructor(
    private readonly devices: DevicesService,
    private readonly backups: DeviceBackupsService,
    private readonly restores: DeviceRestoresService,
    private readonly activity: BackupActivityService,
  ) {}
  @Header("Cache-Control", "private, no-store") @Get() list(
    @Req() req: AuthRequest,
    @Query() query: ListDevicesDto,
  ) {
    return this.devices.list(req.auth.user, query);
  }
  @Get("companies")
  @Header("Cache-Control", "private, no-store")
  companies(@Req() req: AuthRequest) {
    return this.devices.companies(req.auth.user);
  }
  @Get("assets-overview")
  @Header("Cache-Control", "private, no-store")
  assetsOverview(@Req() req: AuthRequest, @Query() query: AssetsOverviewQueryDto) {
    return this.devices.assetsOverview(req.auth.user, query);
  }
  @Get("backups-catalog")
  @Header("Cache-Control", "private, no-store")
  backupCatalog(@Req() req: AuthRequest, @Query() query: BackupCatalogQueryDto) {
    return this.backups.catalog(req.auth.user, query);
  }
  @Get("backup-activity")
  @Header("Cache-Control", "private, no-store")
  backupActivity(@Req() req: AuthRequest, @Query() query: BackupActivityQueryDto) {
    return this.backups.activity(req.auth.user, query);
  }
  @Post("backup-activity-preview")
  @Header("Cache-Control", "private, no-store")
  previewBackupActivity(@Req() req: AuthRequest, @Body() body: BackupActivitySelectionDto) {
    return this.activity.preview(req.auth.user, body);
  }
  @Post("backup-activity-clear")
  @Header("Cache-Control", "private, no-store")
  clearBackupActivity(@Req() req: AuthRequest, @Body() body: ClearBackupHistoryDto) {
    return this.activity.clear(req.auth.user, body.selectionToken);
  }
  @Post("companies")
  createCompany(@Req() req: AuthRequest, @Body() body: CompanyNameDto) {
    return this.devices.createCompany(req.auth.user, body.name);
  }
  @Get("credentials")
  @Header("Cache-Control", "private, no-store")
  credentials(@Req() req: AuthRequest) {
    return this.devices.credentials(req.auth.user);
  }
  @Post("credentials")
  createCredential(@Req() req: AuthRequest, @Body() body: SaveCredentialDto) {
    return this.devices.saveCredential(req.auth.user, body);
  }
  @Put("credentials/:id")
  editCredential(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: SaveCredentialDto,
  ) {
    return this.devices.saveCredential(req.auth.user, body, id);
  }
  @Delete("credentials/:id")
  deleteCredential(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.deleteCredential(req.auth.user, id);
  }
  @Get("registration-draft")
  @Header("Cache-Control", "private, no-store")
  async registrationDraft(@Req() req: AuthRequest) {
    return { draft: await this.devices.registrationDraft(req.auth.user) };
  }

  @Put("registration-draft")
  saveRegistrationDraft(@Req() req: AuthRequest, @Body() body: RegistrationDraftDto) {
    return this.devices.saveRegistrationDraft(req.auth.user, body);
  }

  @Delete("registration-draft")
  deleteRegistrationDraft(@Req() req: AuthRequest, @Query("revision") revision: string) {
    return this.devices.deleteRegistrationDraft(req.auth.user, revision);
  }

  @Header("Cache-Control", "private, no-store") @Get(":id") get(
    @Req() req: AuthRequest,
    @Param("id") id: string,
  ) {
    return this.devices.get(req.auth.user, id);
  }
  @Get(":id/backups")
  @Header("Cache-Control", "private, no-store")
  backupsList(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Query() query: BackupHistoryQueryDto,
  ) {
    return this.backups.list(req.auth.user, id, query);
  }
  @Get(":id/backup-restores")
  @Header("Cache-Control", "private, no-store")
  backupRestores(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.restores.list(req.auth.user, id);
  }
  @Post(":id/backup-restore-preview")
  @Header("Cache-Control", "private, no-store")
  previewRestore(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: PreviewDeviceRestoreDto,
  ) {
    return this.restores.preview(req.auth.user, id, body.artifactId);
  }
  @Post(":id/backup-restores/:planId/execute")
  @HttpCode(202)
  @Header("Cache-Control", "private, no-store")
  executeRestore(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Param("planId", new ParseUUIDPipe({ version: "4" })) planId: string,
    @Body() body: ExecuteDeviceRestoreDto,
  ) {
    return this.restores.execute(req.auth.user, id, planId, body);
  }
  @Post(":id/backup-restores/:planId/verify")
  @Header("Cache-Control", "private, no-store")
  verifyRestore(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Param("planId", new ParseUUIDPipe({ version: "4" })) planId: string,
  ) {
    return this.restores.verify(req.auth.user, id, planId);
  }
  @Post(":id/backup-upload")
  @Header("Cache-Control", "private, no-store")
  backupUpload(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.backups.upload(req.auth.user, id, req.headers["x-backup-filename"], req.body);
  }
  @Get(":id/backups/:backupId/review")
  @Header("Cache-Control", "private, no-store")
  backupReview(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Param("backupId", new ParseUUIDPipe({ version: "4" })) backupId: string,
  ) {
    return this.backups.review(req.auth.user, id, backupId);
  }
  @Post(":id/backup-history-preview")
  @Header("Cache-Control", "private, no-store")
  previewBackupHistory(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: BackupHistorySelectionDto,
  ) {
    return this.backups.previewHistoryClear(req.auth.user, id, body);
  }
  @Post(":id/backup-history-clear")
  @Header("Cache-Control", "private, no-store")
  clearBackupHistory(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: ClearBackupHistoryDto,
  ) {
    return this.backups.clearHistory(req.auth.user, id, body.selectionToken);
  }
  @Post(":id/backups")
  @Header("Cache-Control", "private, no-store")
  backupCreate(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.backups.create(req.auth.user, id);
  }
  @Get(":id/backups/:backupId")
  @Header("Cache-Control", "private, no-store")
  backupDownload(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Param("backupId", new ParseUUIDPipe({ version: "4" })) backupId: string,
  ) {
    return this.backups.download(req.auth.user, id, backupId);
  }
  @Delete(":id/backups/:backupId")
  @Header("Cache-Control", "private, no-store")
  backupDelete(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Param("backupId", new ParseUUIDPipe({ version: "4" })) backupId: string,
  ) {
    return this.backups.deleteFile(req.auth.user, id, backupId);
  }

  @Get(":id/inventory-events")
  @Header("Cache-Control", "private, no-store")
  inventoryEvents(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.inventoryEvents(req.auth.user, id);
  }

  @Get(":id/history")
  @Header("Cache-Control", "private, no-store")
  history(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.history(req.auth.user, id);
  }
  @Post("discover-recorders")
  @Header("Cache-Control", "private, no-store")
  discoverRecorders(@Req() req: AuthRequest, @Body() body: DiscoverRecordersDto) {
    return this.devices.discoverRecorders(req.auth.user, body);
  }

  @Post("draft-connection")
  @Header("Cache-Control", "private, no-store")
  testDraft(@Req() req: AuthRequest, @Body() body: DraftConnectionDto) {
    return this.devices.testDraftConnection(req.auth.user, body);
  }
  @Post() create(@Req() req: AuthRequest, @Body() body: CreateDeviceDto) {
    return this.devices.create(req.auth.user, body);
  }
  @Post(":id/test-connection")
  testConnection(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.testConnection(req.auth.user, id);
  }
  @Post(":id/verify-recorder-stream")
  @Header("Cache-Control", "private, no-store")
  verifyRecorderStream(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: RecorderSnapshotDto,
  ) {
    return this.devices.inspectRecorder(req.auth.user, id, body.token, "stream");
  }

  @Post(":id/recorder-snapshot")
  @Header("Cache-Control", "private, no-store")
  recorderSnapshot(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: RecorderSnapshotDto,
  ) {
    return this.devices.inspectRecorder(req.auth.user, id, body.token);
  }

  @Post(":id/inspect-recorder")
  @Header("Cache-Control", "private, no-store")
  inspectRecorder(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.inspectRecorder(req.auth.user, id);
  }

  @Post(":id/verify-recorder")
  @Header("Cache-Control", "private, no-store")
  verifyRecorder(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: VerifyRecorderDto,
  ) {
    return this.devices.verifySavedRecorder(req.auth.user, id, body);
  }

  @Post(":id/linux-ssh")
  @Header("Cache-Control", "private, no-store")
  linuxSsh(@Req() req: AuthRequest, @Param("id") id: string, @Body() body: LinuxSshDto) {
    return this.devices.linuxSsh(req.auth.user, id, body);
  }
  @Put(":id") update(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: SaveDeviceDto,
  ) {
    return this.devices.update(req.auth.user, id, body);
  }
  @Post(":id/restore")
  restore(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.restore(req.auth.user, id);
  }

  @Delete(":id") archive(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.archive(req.auth.user, id);
  }
}
