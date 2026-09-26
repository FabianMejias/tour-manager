# Cuentas por pagar — Tour Manager

## Arquitectura revisada

La aplicación es Express 5 con PostgreSQL y una interfaz HTML/JavaScript. `/api/state` carga clientes, proveedores, OC, ventas y pagos. El esquema operativo ya existente usa `purchase_orders`, `payments`, `payment_purchase_orders` y `sequences`; las OC guardan además `payment_status`, `payment_date` y `payment_receipt`. Las órdenes se relacionan con las facturas por `sale_id`. El repositorio no contiene la migración inicial completa de estas tablas; la implementación presupone el esquema que ya usa el servidor desplegado.

Antes de este cambio, el navegador creaba pagos dentro de una copia completa del estado y hacía `PUT /api/state`. Esa ruta reconstruía todos los vínculos de pago, con riesgo de borrar un vínculo recién creado por otra sesión. El consecutivo también se calculaba en el navegador.

## Cambios

- La pantalla CxP tiene vistas de **Pendientes y corte** e **Historial y comprobantes**. La fecha de corte filtra por fecha de servicio. Sigue disponible el filtro por proveedor, búsqueda y selección de varias OC del mismo proveedor.
- Cada OC ofrece vista previa de la orden y, si existe, de su factura. Los servicios futuros se señalan; el formulario admite marcar el pago como prepago, notas, fecha y número de comprobante.
- `POST /api/payments` exige sesión y `payments.create`, valida la selección y registra el pago en una sola transacción PostgreSQL. Bloquea las OC, rechaza órdenes canceladas, ya pagadas o vinculadas, mezcla de proveedores o monedas y servicios futuros sin marca de prepago. Incrementa `sequences.P` dentro de la transacción y escribe el pago, sus relaciones y el estado de las OC.
- Una migración aditiva al iniciar el servidor agrega `payments.is_prepayment BOOLEAN NOT NULL DEFAULT FALSE`. Los pagos previos se leen como pagos ordinarios; se conservan sus números y relaciones. El comprobante muestra tipo y notas y se puede imprimir o guardar como PDF con la función existente.
- La ruta heredada `PUT /api/state` ya no borra relaciones de pago y conserva la edición anterior de pagos existentes. Tampoco regresa a pendiente el estado de una OC marcada pagada en la base de datos. Permanece para las funciones antiguas mientras se migran otros módulos.

## Despliegue y compatibilidad

No se requiere convertir OC ni pagos históricos. La cuenta de PostgreSQL usada por Railway debe poder ejecutar `ALTER TABLE payments`; el servidor espera a que termine la migración antes de atender peticiones. Desplegar primero el código del servidor y la interfaz en la misma versión. Conservar un respaldo de PostgreSQL antes del despliegue y comprobar en una copia de datos reales: OC pendiente, OC histórica pagada, servicio futuro, pago de varias OC, vista previa de factura y comprobante, y dos sesiones intentando pagar la misma OC.

La ruta general de estado todavía acepta escrituras de módulos anteriores; conviene migrarlos a operaciones individuales para evitar ediciones concurrentes de esos otros registros. Los pagos son completos por OC: no se implementan pagos parciales ni saldos a favor sin OC. La moneda de un pago se deduce de sus OC y se prohíbe mezclar monedas.

## Verificación local

`node --check server.js`, compilación de JavaScript del bloque principal del HTML mediante `new Function`, y `git diff --check`. No hubo conexión autorizada a la base de datos de producción ni se ejecutó una migración allí; las pruebas transaccionales descritas arriba deben ejecutarse con una base de prueba antes del despliegue.
