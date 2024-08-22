import { Allow } from 'class-validator';
import databaseConfig from '../../database/config/database.config';
import { DatabaseConfig } from '../../database/config/database-config.type';

// <database-block>
const idType = (databaseConfig() as DatabaseConfig).isDocumentDatabase
  ? String
  : Number;
// </database-block>

export class Role {
  @Allow()
  id: number | string;

  @Allow()
  name?: string;
}
