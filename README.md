# Tour Manager Online V1

Primera etapa de migración de Tour Manager V2.0 a Railway + PostgreSQL.

## Arquitectura
- Node.js + Express
- PostgreSQL de Railway
- Frontend actual de Tour Manager V2.0
- API `/api/health`, `/api/state` GET/PUT

## Railway
El servicio de aplicación debe recibir automáticamente `DATABASE_URL` desde el servicio Postgres mediante una referencia de variable en Railway.

## Importante
La V1 utiliza una sincronización transaccional de estado completo para conservar la lógica de la V2.0 durante la primera migración. Es una etapa puente: una siguiente iteración puede pasar a endpoints CRUD por módulo y autenticación/roles.
