const express = require('express');
const helmet = require('helmet');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: '2mb' }));
// ============================================================
// TOUR MANAGER - AUTENTICACION Y PERMISOS
// ============================================================
const bcrypt = require('bcryptjs');
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET || 'CHANGE-THIS-SESSION-SECRET',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

const TM_PERMISSIONS = [
  'dashboard.view',
  'clients.view','clients.create','clients.edit','clients.delete',
  'suppliers.view','suppliers.create','suppliers.edit','suppliers.delete',
  'sellers.view','sellers.create','sellers.edit','sellers.delete',
  'tours.view','tours.create','tours.edit','tours.delete',
  'purchase_orders.view','purchase_orders.create','purchase_orders.edit','purchase_orders.delete',
  'sales.view','sales.create','sales.edit','sales.delete',
  'payments.view','payments.create','payments.edit','payments.delete',
  'reports.service_dates.view',
  'reports.sellers.view',
  'reports.sales_analysis.view',
  'reports.best_sellers.view',
  'users.view','users.create','users.edit','users.delete',
  'settings.view','settings.edit'
];

app.get('/api/auth/status', async (req,res)=>{
  try {
    const r=await pool.query('SELECT COUNT(*)::int AS count FROM users');
    res.json({userCount:r.rows[0].count, authenticated:!!req.session.user, user:req.session.user||null});
  } catch(e){ res.status(500).json({error:'No fue posible consultar el estado de autenticación.'}); }
});

app.post('/api/auth/bootstrap', async (req,res)=>{
  try {
    const count=await pool.query('SELECT COUNT(*)::int AS count FROM users');
    if(count.rows[0].count!==0) return res.status(409).json({error:'Ya existe un usuario. Utiliza el inicio de sesión.'});
    const {name,email,password}=req.body||{};
    if(!name||!email||!password||String(password).length<8) return res.status(400).json({error:'Nombre, correo y una contraseña de al menos 8 caracteres son obligatorios.'});
    const hash=await bcrypt.hash(String(password),12);
    const r=await pool.query(`INSERT INTO users(name,email,password_hash,role,active) VALUES($1,$2,$3,'admin',true) RETURNING id,name,email,role,active`,[String(name).trim(),String(email).trim().toLowerCase(),hash]);
    req.session.user=r.rows[0];
    res.status(201).json({user:r.rows[0]});
  } catch(e){ res.status(500).json({error:'No fue posible crear el administrador inicial.'}); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
    const r = await pool.query(
      'SELECT id,name,email,password_hash,role,active FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [String(email).trim()]
    );
    if (!r.rows.length || !r.rows[0].active) return res.status(401).json({ error: 'Credenciales inválidas.' });
    const u = r.rows[0];
    if (!(await bcrypt.compare(String(password), u.password_hash))) {
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }
    req.session.user = { id: u.id, name: u.name, email: u.email, role: u.role };
    res.json({ user: req.session.user });
  } catch (e) {
    res.status(500).json({ error: 'No fue posible iniciar sesión.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ authenticated: false });
  const r = await pool.query(
    'SELECT id,name,email,role,active FROM users WHERE id=$1 LIMIT 1',
    [req.session.user.id]
  );
  if (!r.rows.length || !r.rows[0].active) {
    return req.session.destroy(() => res.status(401).json({ authenticated: false }));
  }
  res.json({ authenticated: true, user: r.rows[0] });
});

app.get('/api/auth/permissions', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado.' });
  if (req.session.user.role === 'admin') return res.json({ permissions: TM_PERMISSIONS });
  const r = await pool.query(
    'SELECT permission FROM user_permissions WHERE user_id=$1 AND allowed=true ORDER BY permission',
    [req.session.user.id]
  );
  res.json({ permissions: r.rows.map(x => x.permission) });
});

// Initial user administration endpoints.
// They are intentionally protected by the admin role while the UI is being completed.
app.get('/api/users', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado.' });
  const r = await pool.query(
    'SELECT id,name,email,role,active,created_at,updated_at FROM users ORDER BY name'
  );
  res.json({ users: r.rows });
});

app.post('/api/users', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado.' });
  const { name, email, password, role='user', active=true } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Nombre, correo y contraseña son obligatorios.' });
  const hash = await bcrypt.hash(String(password), 12);
  try {
    const r = await pool.query(
      `INSERT INTO users(name,email,password_hash,role,active)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id,name,email,role,active,created_at`,
      [String(name).trim(), String(email).trim().toLowerCase(), hash, role, !!active]
    );
    res.status(201).json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese correo ya está registrado.' });
    res.status(500).json({ error: 'No fue posible crear el usuario.' });
  }
});

app.patch('/api/users/:id', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado.' });
  const { name, email, role, active, password } = req.body || {};
  const fields = [], vals = [];
  if (name !== undefined) { fields.push(`name=$${vals.length+1}`); vals.push(String(name).trim()); }
  if (email !== undefined) { fields.push(`email=$${vals.length+1}`); vals.push(String(email).trim().toLowerCase()); }
  if (role !== undefined) { fields.push(`role=$${vals.length+1}`); vals.push(role); }
  if (active !== undefined) { fields.push(`active=$${vals.length+1}`); vals.push(!!active); }
  if (password) { fields.push(`password_hash=$${vals.length+1}`); vals.push(await bcrypt.hash(String(password),12)); }
  if (!fields.length) return res.status(400).json({ error: 'No hay cambios.' });
  vals.push(req.params.id);
  try {
    const r = await pool.query(
      `UPDATE users SET ${fields.join(', ')}, updated_at=NOW() WHERE id=$${vals.length}
       RETURNING id,name,email,role,active,updated_at`,
      vals
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Usuario no encontrado.' });
    res.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese correo ya está registrado.' });
    res.status(500).json({ error: 'No fue posible actualizar el usuario.' });
  }
});

app.get('/api/users/:id/permissions', async (req,res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({error:'Acceso denegado.'});
  const r = await pool.query(
    'SELECT permission,allowed FROM user_permissions WHERE user_id=$1 ORDER BY permission',
    [req.params.id]
  );
  res.json({permissions:r.rows});
});

app.put('/api/users/:id/permissions', async (req,res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({error:'Acceso denegado.'});
  const permissions = Array.isArray(req.body?.permissions) ? req.body.permissions : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const old = await client.query('SELECT permission,allowed FROM user_permissions WHERE user_id=$1',[req.params.id]);
    const oldMap = Object.fromEntries(old.rows.map(x=>[x.permission,x.allowed]));
    await client.query('DELETE FROM user_permissions WHERE user_id=$1',[req.params.id]);
    for (const p of TM_PERMISSIONS) {
      const allowed = permissions.includes(p);
      await client.query(
        `INSERT INTO user_permissions(user_id,permission,allowed)
         VALUES($1,$2,$3)`,
        [req.params.id,p,allowed]
      );
      if (oldMap[p] !== allowed) {
        await client.query(
          `INSERT INTO user_permission_audit(changed_by,user_id,permission,old_allowed,new_allowed)
           VALUES($1,$2,$3,$4,$5)`,
          [req.session.user.id,req.params.id,p,oldMap[p] ?? false,allowed]
        );
      }
    }
    await client.query('COMMIT');
    res.json({ok:true});
  } catch(e) {
    await client.query('ROLLBACK');
    res.status(500).json({error:'No fue posible guardar los permisos.'});
  } finally {
    client.release();
  }
});


// ============================================================
// ORDENES DE COMPRA - OPERACIONES INDIVIDUALES / MULTIUSUARIO
// ============================================================

async function tmHasPermission(req, permission) {
  if (!req.session.user) return false;
  if (req.session.user.role === 'admin') return true;

  const r = await pool.query(
    'SELECT 1 FROM user_permissions WHERE user_id=$1 AND permission=$2 AND allowed=true LIMIT 1',
    [req.session.user.id, permission]
  );

  return r.rows.length > 0;
}

app.post('/api/purchase-orders', async (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ error: 'No autenticado.' });

  if (!(await tmHasPermission(req, 'purchase_orders.create')))
    return res.status(403).json({ error: 'No tiene permiso para crear órdenes de compra.' });

  const d = req.body || {};

  if (!d.clientId || !d.supplierId || !d.sellerId || !d.tourId ||
      !d.customerName || !d.serviceDate) {
    return res.status(400).json({
      error: 'Faltan datos obligatorios de la orden de compra.'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Reservar consecutivo de OC de forma atómica.
    // Se toma el mayor valor entre la secuencia y las OCs existentes
    // para evitar desincronizaciones de consecutivos.
    const ocSeq = await client.query(`
      SELECT current_value
      FROM sequences
      WHERE code='OC'
      FOR UPDATE
    `);

    const maxOc = await client.query(`
      SELECT COALESCE(
        MAX(CAST(SUBSTRING(number FROM 4) AS INTEGER)),
        0
      ) AS max_number
      FROM purchase_orders
      WHERE number ~ '^OC-[0-9]+$'
    `);

    const nextOc = Math.max(
      Math.max(Number(ocSeq.rows[0]?.current_value || 0), 4699),
      Number(maxOc.rows[0]?.max_number || 0)
    ) + 1;

    await client.query(`
      INSERT INTO sequences(code,current_value)
      VALUES('OC',$1)
      ON CONFLICT(code)
      DO UPDATE SET current_value=EXCLUDED.current_value
    `, [nextOc]);

    // Reservar consecutivo de operación de forma atómica.
    // OP puede estar relacionado con ventas u OCs, por lo que
    // se toma el mayor valor existente en ambas tablas.
    const opSeq = await client.query(`
      SELECT current_value
      FROM sequences
      WHERE code='OP'
      FOR UPDATE
    `);

    const maxOp = await client.query(`
      SELECT GREATEST(
        COALESCE((
          SELECT MAX(CAST(SUBSTRING(operation_number FROM 4) AS INTEGER))
          FROM purchase_orders
          WHERE operation_number ~ '^OP-[0-9]+$'
        ),0),
        COALESCE((
          SELECT MAX(CAST(SUBSTRING(operation_number FROM 4) AS INTEGER))
          FROM sales
          WHERE operation_number ~ '^OP-[0-9]+$'
        ),0)
      ) AS max_number
    `);

    const nextOp = Math.max(
      Math.max(Number(opSeq.rows[0]?.current_value || 0), 4699),
      Number(maxOp.rows[0]?.max_number || 0)
    ) + 1;

    await client.query(`
      INSERT INTO sequences(code,current_value)
      VALUES('OP',$1)
      ON CONFLICT(code)
      DO UPDATE SET current_value=EXCLUDED.current_value
    `, [nextOp]);

    const number = 'OC-' + String(nextOc).padStart(6, '0');
    const operationNumber = 'OP-' + String(nextOp).padStart(6, '0');
    const id = d.id || require('crypto').randomUUID();

    // ============================================================
    // TARIFA VIGENTE PARA OC NUEVA
    // ============================================================
    // Busca la tarifa utilizando:
    //   TOUR + FECHA DEL SERVICIO
    //
    // Solo afecta OCs nuevas.
    // Las OCs existentes conservan su costo.
    //
    // Si no existe una tarifa para esa fecha, se mantiene
    // el costo ingresado manualmente por el vendedor.
    // ============================================================

    let finalUnitCost = Number(d.unitCost || 0);

    const rateResult = await client.query(`
      SELECT
        id,
        cost,
        sale_price,
        valid_from,
        valid_to
      FROM tour_rates
      WHERE tour_id=$1
        AND active=TRUE
        AND valid_from <= $2::date
        AND valid_to >= $2::date
      ORDER BY valid_from DESC
      LIMIT 1
    `, [
      d.tourId,
      d.serviceDate
    ]);

    if (rateResult.rows.length) {
      finalUnitCost = Number(rateResult.rows[0].cost || 0);
    }

    // Recalcular los importes utilizando el costo de la tarifa.
    const finalPassengers = Number(d.pax || 1);
    const finalSubtotal = finalUnitCost * finalPassengers;
    const finalTaxRate = Number(d.taxRate ?? 13);
    const finalTaxAmount = finalSubtotal * (finalTaxRate / 100);
    const finalTotal = finalSubtotal + finalTaxAmount;


    const r = await client.query(`
      INSERT INTO purchase_orders(
        id,
        number,
        operation_number,
        client_id,
        supplier_id,
        seller_id,
        tour_id,
        client_name,
        issue_date,
        service_date,
        service_time,
        pickup_place,
        drop_off,
        passengers,
        unit_cost,
        subtotal,
        tax_rate,
        tax_amount,
        total,
        currency,
        notes,
        payment_status,
        payment_date,
        payment_receipt,
        sale_id
      )
      VALUES(
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
        $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25
      )
      RETURNING *
    `, [
      id,
      number,
      operationNumber,
      d.clientId,
      d.supplierId,
      d.sellerId,
      d.tourId,
      String(d.customerName).trim(),
      d.issueDate || new Date().toISOString().slice(0,10),
      d.serviceDate,
      d.time || null,
      d.place || null,
      d.dropOff || null,
      finalPassengers,
      finalUnitCost,
      finalSubtotal,
      finalTaxRate,
      finalTaxAmount,
      finalTotal,
      d.currency || 'USD',
      d.notes || null,
      'Pendiente',
      null,
      null,
      null
    ]);

    await client.query('COMMIT');

    res.status(201).json({ order: r.rows[0] });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error creando OC:', e);

    if (e.code === '23505')
      return res.status(409).json({
        error: 'El consecutivo de la OC u operación ya existe. Intente nuevamente.'
      });

    res.status(500).json({
      error: 'No fue posible crear la orden de compra.'
    });

  } finally {
    client.release();
  }
});


app.put('/api/purchase-orders/:id', async (req, res) => {

  if (!req.session.user)
    return res.status(401).json({ error: 'No autenticado.' });

  if (!(await tmHasPermission(req, 'purchase_orders.edit')))
    return res.status(403).json({ error: 'No tiene permiso para editar órdenes de compra.' });

  const d = req.body || {};

  if (!d.updatedAt)
    return res.status(400).json({
      error: 'No se recibió la versión de la OC. Recargue la información e intente nuevamente.'
    });

  const client = await pool.connect();

  try {

    await client.query('BEGIN');

    // Verificar la versión actual dentro de la misma transacción.
    // Se compara como timestamp para evitar diferencias de representación
    // entre PostgreSQL y JavaScript.
    const current = await client.query(`
      SELECT *
      FROM purchase_orders
      WHERE id=$1
      FOR UPDATE
    `, [req.params.id]);

    if (!current.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        error: 'Orden de compra no encontrada.'
      });
    }

    const currentOrder = current.rows[0];
    const currentUpdatedAt = new Date(currentOrder.updated_at).getTime();
    const receivedUpdatedAt = new Date(d.updatedAt).getTime();

    if (
      !Number.isFinite(currentUpdatedAt) ||
      !Number.isFinite(receivedUpdatedAt) ||
      currentUpdatedAt !== receivedUpdatedAt
    ) {
      await client.query('ROLLBACK');

      return res.status(409).json({
        error: 'Esta OC fue modificada por otro usuario. Recargue la información antes de guardarla.',
        conflict: true,
        order: currentOrder
      });
    }

    const r = await client.query(`
      UPDATE purchase_orders
      SET
        client_id=$1,
        supplier_id=$2,
        seller_id=$3,
        tour_id=$4,
        client_name=$5,
        issue_date=$6,
        service_date=$7,
        service_time=$8,
        pickup_place=$9,
        drop_off=$10,
        passengers=$11,
        unit_cost=$12,
        subtotal=$13,
        tax_rate=$14,
        tax_amount=$15,
        total=$16,
        currency=$17,
        notes=$18,
        updated_at=NOW(),
        updated_by_user_id=$20
      WHERE id=$19
      RETURNING *
    `, [
      d.clientId,
      d.supplierId,
      d.sellerId,
      d.tourId,
      String(d.customerName || '').trim(),
      d.issueDate || null,
      d.serviceDate || null,
      d.time || null,
      d.place || null,
      d.dropOff || null,
      Number(d.pax || 1),
      Number(d.unitCost || 0),
      Number(d.subtotal || 0),
      Number(d.taxRate || 0),
      Number(d.tax || 0),
      Number(d.total || 0),
      d.currency || 'USD',
      d.notes || null,
      req.params.id,
      req.session.user.id
    ]);

    await client.query('COMMIT');

    res.json({ order: r.rows[0] });

  } catch (e) {

    await client.query('ROLLBACK');

    console.error('Error actualizando OC:', e);

    res.status(500).json({
      error: 'No fue posible actualizar la orden de compra.'
    });

  } finally {

    client.release();

  }

});

app.delete('/api/purchase-orders/:id', async (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ error: 'No autenticado.' });

  if (!(await tmHasPermission(req, 'purchase_orders.delete')))
    return res.status(403).json({ error: 'No tiene permiso para eliminar órdenes de compra.' });

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const check = await client.query(`
      SELECT
        id,
        number,
        sale_id,
        EXISTS(
          SELECT 1
          FROM payment_purchase_orders ppo
          WHERE ppo.purchase_order_id = purchase_orders.id
        ) AS has_payment
      FROM purchase_orders
      WHERE id=$1
      FOR UPDATE
    `, [req.params.id]);

    if (!check.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Orden de compra no encontrada.' });
    }

    const o = check.rows[0];

    if (o.sale_id || o.has_payment) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'No se puede eliminar una OC que ya tiene factura o pago asociado.'
      });
    }

    await client.query(
      'DELETE FROM purchase_orders WHERE id=$1',
      [req.params.id]
    );

    await client.query('COMMIT');

    res.json({ ok: true });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error eliminando OC:', e);

    res.status(500).json({
      error: 'No fue posible eliminar la orden de compra.'
    });

  } finally {
    client.release();
  }
});


const port = process.env.PORT || 3000;
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL no está configurada. En Railway se inyecta automáticamente al conectar el servicio Postgres.');
  process.exit(1);
}

const pool = new Pool({ connectionString: databaseUrl, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, 'public')));

const q = (text, params=[]) => pool.query(text, params);


// ============================================================
// TARIFAS POR VIGENCIA DE TOURS
// ============================================================
// Esta migración es aditiva.
// No elimina ni modifica OCs, ventas ni tours existentes.
//
// Cada tarifa pertenece a un TOUR y tiene:
// - fecha inicial
// - fecha final
// - costo
// - precio de venta
// - estado activo
//
// Las OCs existentes conservan sus propios valores.
// ============================================================

(async () => {
  try {

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tour_rates (
        id UUID PRIMARY KEY,
        tour_id UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
        valid_from DATE NOT NULL,
        valid_to DATE NOT NULL,
        cost NUMERIC(14,2) NOT NULL DEFAULT 0,
        sale_price NUMERIC(14,2) NOT NULL DEFAULT 0,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        CONSTRAINT tour_rates_valid_dates
          CHECK (valid_to >= valid_from),

        CONSTRAINT tour_rates_cost_nonnegative
          CHECK (cost >= 0),

        CONSTRAINT tour_rates_sale_nonnegative
          CHECK (sale_price >= 0)
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_tour_rates_tour
      ON tour_rates(tour_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_tour_rates_dates
      ON tour_rates(tour_id, valid_from, valid_to)
    `);

    console.log('OK: estructura de tarifas por vigencia disponible.');

  } catch (e) {
    console.error(
      'ERROR creando tarifas por vigencia:',
      e.message
    );
  }
})();


// ============================================================
// AUDITORIA DE OCs
// Registra automáticamente quién realizó la última modificación.
// La migración es aditiva y no elimina ni modifica información existente.
// ============================================================
(async () => {
  try {
    await pool.query(`
      ALTER TABLE purchase_orders
      ADD COLUMN IF NOT EXISTS updated_by_user_id UUID
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_purchase_orders_updated_by_user
      ON purchase_orders(updated_by_user_id)
    `);

    console.log('OK: auditoría de OCs disponible.');
  } catch (e) {
    console.error('ERROR creando auditoría de OCs:', e.message);
  }
})();



// ============================================================
// CARGA INICIAL DE TARIFAS DE TOURS
// ============================================================
// Crea una tarifa base para los Tours que todavía no tengan
// ninguna tarifa configurada.
//
// La tarifa base conserva los valores actuales:
//   tours.cost        -> costo
//   tours.hotel_price -> precio de venta
//
// La vigencia inicial llega hasta 31/12/2026.
// Las tarifas de 2027 y futuras se configurarán posteriormente.
//
// IMPORTANTE:
// - No modifica tours.
// - No modifica OCs.
// - No modifica ventas.
// - No modifica pagos.
// - No elimina registros.
// - No duplica tarifas si ya existen.
// ============================================================

(async () => {
  try {

    const result = await pool.query(`
      INSERT INTO tour_rates (
        id,
        tour_id,
        valid_from,
        valid_to,
        cost,
        sale_price,
        active
      )
      SELECT
        gen_random_uuid(),
        t.id,
        DATE '2026-01-01',
        DATE '2026-12-31',
        COALESCE(t.cost, 0),
        COALESCE(t.hotel_price, 0),
        TRUE
      FROM tours t
      WHERE NOT EXISTS (
        SELECT 1
        FROM tour_rates tr
        WHERE tr.tour_id = t.id
      )
      RETURNING id
    `);

    console.log(
      'OK: tarifas base creadas:',
      result.rowCount
    );

  } catch (e) {
    console.error(
      'ERROR cargando tarifas base:',
      e.message
    );
  }
})();



// ============================================================
// AJUSTE DE VIGENCIA INICIAL 2026
// ============================================================
// La tarifa base inicial fue creada con vigencia:
// 01/01/2026 -> 31/12/2026.
//
// Para el inicio del sistema de vigencias, se ajusta únicamente
// esa tarifa base a:
// 01/01/2026 -> 15/12/2026.
//
// IMPORTANTE:
// - No modifica costo.
// - No modifica precio de venta.
// - No modifica estado.
// - No modifica tours.
// - No modifica OCs.
// - No modifica ventas.
// - No modifica pagos.
// - Es idempotente.
// ============================================================

(async () => {
  try {

    const result = await pool.query(`
      UPDATE tour_rates
      SET
        valid_to = DATE '2026-12-15',
        updated_at = NOW()
      WHERE
        valid_from = DATE '2026-01-01'
        AND valid_to = DATE '2026-12-31'
    `);

    console.log(
      'OK: vigencias 2026 ajustadas a 15/12/2026:',
      result.rowCount
    );

  } catch (e) {

    console.error(
      'ERROR ajustando vigencias 2026:',
      e.message
    );

  }
})();

// ============================================================
// API — TARIFAS POR VIGENCIA
// ============================================================

app.get('/api/tour-rates/:tourId', async (req,res) => {
  if (!req.session.user)
    return res.status(401).json({error:'No autenticado.'});

  try {
    const r = await pool.query(`
      SELECT
        id,
        tour_id,
        valid_from,
        valid_to,
        cost,
        sale_price,
        active,
        created_at,
        updated_at
      FROM tour_rates
      WHERE tour_id=$1
      ORDER BY valid_from ASC, valid_to ASC
    `,[req.params.tourId]);

    res.json({
      rates:r.rows.map(x=>({
        id:x.id,
        tourId:x.tour_id,
        validFrom:x.valid_from,
        validTo:x.valid_to,
        cost:Number(x.cost||0),
        salePrice:Number(x.sale_price||0),
        active:x.active,
        createdAt:x.created_at,
        updatedAt:x.updated_at
      }))
    });

  } catch(e) {
    console.error('Error consultando tarifas:',e);
    res.status(500).json({
      error:'No fue posible consultar las tarifas.'
    });
  }
});


app.post('/api/tour-rates', async (req,res) => {
  if (!req.session.user)
    return res.status(401).json({error:'No autenticado.'});

  const {
    tourId,
    validFrom,
    validTo,
    cost,
    salePrice,
    active=true
  } = req.body || {};

  if (!tourId || !validFrom || !validTo)
    return res.status(400).json({
      error:'Tour, fecha inicial y fecha final son obligatorios.'
    });

  const costNumber=Number(cost);
  const saleNumber=Number(salePrice);

  if (!Number.isFinite(costNumber) || costNumber<0)
    return res.status(400).json({
      error:'El costo debe ser un número mayor o igual a cero.'
    });

  if (!Number.isFinite(saleNumber) || saleNumber<0)
    return res.status(400).json({
      error:'El precio de venta debe ser un número mayor o igual a cero.'
    });

  if (validTo < validFrom)
    return res.status(400).json({
      error:'La fecha final no puede ser anterior a la fecha inicial.'
    });

  try {

    const overlap = await pool.query(`
      SELECT id
      FROM tour_rates
      WHERE tour_id=$1
        AND active=TRUE
        AND $2::date <= valid_to
        AND $3::date >= valid_from
      LIMIT 1
    `,[tourId,validFrom,validTo]);

    if (overlap.rows.length)
      return res.status(409).json({
        error:'Las fechas se superponen con otra tarifa activa de este tour.'
      });

    const r = await pool.query(`
      INSERT INTO tour_rates(
        id,
        tour_id,
        valid_from,
        valid_to,
        cost,
        sale_price,
        active
      )
      VALUES(
        gen_random_uuid(),
        $1,
        $2,
        $3,
        $4,
        $5,
        $6
      )
      RETURNING
        id,
        tour_id,
        valid_from,
        valid_to,
        cost,
        sale_price,
        active,
        created_at,
        updated_at
    `,[
      tourId,
      validFrom,
      validTo,
      costNumber,
      saleNumber,
      active !== false
    ]);

    const x=r.rows[0];

    res.json({
      rate:{
        id:x.id,
        tourId:x.tour_id,
        validFrom:x.valid_from,
        validTo:x.valid_to,
        cost:Number(x.cost||0),
        salePrice:Number(x.sale_price||0),
        active:x.active,
        createdAt:x.created_at,
        updatedAt:x.updated_at
      }
    });

  } catch(e) {
    console.error('Error creando tarifa:',e);
    res.status(500).json({
      error:'No fue posible crear la tarifa.'
    });
  }
});


app.put('/api/tour-rates/:id', async (req,res) => {
  if (!req.session.user)
    return res.status(401).json({error:'No autenticado.'});

  const {
    validFrom,
    validTo,
    cost,
    salePrice,
    active
  } = req.body || {};

  if (!validFrom || !validTo)
    return res.status(400).json({
      error:'Fecha inicial y fecha final son obligatorias.'
    });

  const costNumber=Number(cost);
  const saleNumber=Number(salePrice);

  if (!Number.isFinite(costNumber) || costNumber<0)
    return res.status(400).json({
      error:'El costo debe ser un número mayor o igual a cero.'
    });

  if (!Number.isFinite(saleNumber) || saleNumber<0)
    return res.status(400).json({
      error:'El precio de venta debe ser un número mayor o igual a cero.'
    });

  if (validTo < validFrom)
    return res.status(400).json({
      error:'La fecha final no puede ser anterior a la fecha inicial.'
    });

  try {

    const current = await pool.query(`
      SELECT id,tour_id,active
      FROM tour_rates
      WHERE id=$1
    `,[req.params.id]);

    if (!current.rows.length)
      return res.status(404).json({
        error:'Tarifa no encontrada.'
      });

    const tourId=current.rows[0].tour_id;
    const isActive=active !== false;

    if (isActive) {

      const overlap = await pool.query(`
        SELECT id
        FROM tour_rates
        WHERE tour_id=$1
          AND id<>$2
          AND active=TRUE
          AND $3::date <= valid_to
          AND $4::date >= valid_from
        LIMIT 1
      `,[
        tourId,
        req.params.id,
        validFrom,
        validTo
      ]);

      if (overlap.rows.length)
        return res.status(409).json({
          error:'Las fechas se superponen con otra tarifa activa de este tour.'
        });
    }

    const r=await pool.query(`
      UPDATE tour_rates
      SET
        valid_from=$1,
        valid_to=$2,
        cost=$3,
        sale_price=$4,
        active=$5,
        updated_at=NOW()
      WHERE id=$6
      RETURNING
        id,
        tour_id,
        valid_from,
        valid_to,
        cost,
        sale_price,
        active,
        created_at,
        updated_at
    `,[
      validFrom,
      validTo,
      costNumber,
      saleNumber,
      isActive,
      req.params.id
    ]);

    const x=r.rows[0];

    res.json({
      rate:{
        id:x.id,
        tourId:x.tour_id,
        validFrom:x.valid_from,
        validTo:x.valid_to,
        cost:Number(x.cost||0),
        salePrice:Number(x.sale_price||0),
        active:x.active,
        createdAt:x.created_at,
        updatedAt:x.updated_at
      }
    });

  } catch(e) {
    console.error('Error actualizando tarifa:',e);
    res.status(500).json({
      error:'No fue posible actualizar la tarifa.'
    });
  }
});


app.patch('/api/tour-rates/:id/status', async (req,res) => {
  if (!req.session.user)
    return res.status(401).json({error:'No autenticado.'});

  const active=req.body?.active;

  if (typeof active!=='boolean')
    return res.status(400).json({
      error:'El estado debe ser verdadero o falso.'
    });

  try {

    const r=await pool.query(`
      UPDATE tour_rates
      SET
        active=$1,
        updated_at=NOW()
      WHERE id=$2
      RETURNING
        id,
        tour_id,
        valid_from,
        valid_to,
        cost,
        sale_price,
        active,
        created_at,
        updated_at
    `,[active,req.params.id]);

    if (!r.rows.length)
      return res.status(404).json({
        error:'Tarifa no encontrada.'
      });

    const x=r.rows[0];

    res.json({
      rate:{
        id:x.id,
        tourId:x.tour_id,
        validFrom:x.valid_from,
        validTo:x.valid_to,
        cost:Number(x.cost||0),
        salePrice:Number(x.sale_price||0),
        active:x.active,
        createdAt:x.created_at,
        updatedAt:x.updated_at
      }
    });

  } catch(e) {
    console.error('Error cambiando estado de tarifa:',e);
    res.status(500).json({
      error:'No fue posible cambiar el estado de la tarifa.'
    });
  }
});


app.get('/api/health', async (req,res) => {
  try { const r=await q('SELECT NOW() AS now'); res.json({ok:true, database:true, time:r.rows[0].now}); }
  catch(e){ res.status(500).json({ok:false,error:'Database connection failed'}); }
});

async function getState(client) {
  const [clients,suppliers,sellers,tours,orders,sales,payments,links,sequences,settings,users] = await Promise.all([
    client.query(`SELECT id,name,type,phone,email,currency,notes,active FROM clients ORDER BY name`),
    client.query(`SELECT id,name,contact,phone,email,notes,active FROM suppliers ORDER BY name`),
    client.query(`SELECT id,name,email,phone,commission_rate,active FROM sellers ORDER BY name`),
    client.query(`
      SELECT
        t.id,
        t.name,
        t.hotel_price,
        t.cost,
        t.currency,
        t.active,
        rate.cost AS current_rate_cost,
        rate.sale_price AS current_rate_sale_price,
        rate.valid_from AS current_rate_from,
        rate.valid_to AS current_rate_to,
        rate.active AS current_rate_active
      FROM tours t
      LEFT JOIN LATERAL (
        SELECT
          tr.cost,
          tr.sale_price,
          tr.valid_from,
          tr.valid_to,
          tr.active
        FROM tour_rates tr
        WHERE tr.tour_id = t.id
          AND tr.active = TRUE
          AND CURRENT_DATE BETWEEN tr.valid_from AND tr.valid_to
        ORDER BY tr.valid_from DESC
        LIMIT 1
      ) rate ON TRUE
      ORDER BY t.name
    `),
    client.query(`SELECT id,number,operation_number,client_id,supplier_id,seller_id,tour_id,client_name,issue_date,service_date,service_time,pickup_place,drop_off,passengers,unit_cost,subtotal,tax_rate,tax_amount,total,currency,notes,payment_status,payment_date,payment_receipt,sale_id,updated_at,updated_by_user_id FROM purchase_orders ORDER BY number DESC`),
    client.query(`SELECT id,number,operation_number,client_id,seller_id,tour_id,client_name,service_date,passengers,unit_price,subtotal,discount_percent,discount_amount,taxable_amount,tax_rate,tax_amount,total,currency FROM sales ORDER BY number DESC`),
    client.query(`SELECT id,number,supplier_id,payment_date,receipt_number,total,notes FROM payments ORDER BY number DESC`),
    client.query(`SELECT payment_id,purchase_order_id,amount FROM payment_purchase_orders`),
    client.query(`SELECT code,current_value FROM sequences`),
    client.query(`SELECT commercial_name,legal_name,legal_id,phone,whatsapp,email,address,default_tax_rate FROM company_settings WHERE id=1`),
    client.query(`SELECT id,name,email,role,active FROM users ORDER BY name`)
  ]);
  const byId = (rows) => Object.fromEntries(rows.map(r=>[r.id,r]));
  const cs=byId(clients.rows), ss=byId(suppliers.rows), vs=byId(sellers.rows), ts=byId(tours.rows);
  const usersById=byId(users.rows);
  return {
    clients: clients.rows.map(x=>({id:x.id,name:x.name,type:x.type||'',phone:x.phone||'',email:x.email||'',currency:x.currency||'USD',notes:x.notes||''})),
    suppliers: suppliers.rows.map(x=>({id:x.id,name:x.name,contact:x.contact||'',phone:x.phone||'',email:x.email||'',notes:x.notes||''})),
    sellers: sellers.rows.map(x=>({id:x.id,name:x.name,email:x.email||'',phone:x.phone||'',commissionRate:Number(x.commission_rate||0)})),
    tours: tours.rows.map(x=>({
      id:x.id,
      name:x.name,
      hotel:Number(
        x.current_rate_sale_price ??
        x.hotel_price ??
        0
      ),
      cost:Number(
        x.current_rate_cost ??
        x.cost ??
        0
      ),
      currency:x.currency||'USD',
      currentRateFrom:x.current_rate_from,
      currentRateTo:x.current_rate_to,
      currentRateActive:x.current_rate_active
    })),
    orders: orders.rows.map(x=>({id:x.id,number:x.number,op:x.operation_number,clientId:x.client_id,client:cs[x.client_id]?.name||'',supplierId:x.supplier_id,sellerId:x.seller_id,tourId:x.tour_id,customerName:x.client_name,issueDate:x.issue_date,serviceDate:x.service_date,time:x.service_time,place:x.pickup_place||'',dropOff:x.drop_off||'',pax:x.passengers,unitCost:Number(x.unit_cost||0),subtotal:Number(x.subtotal||0),taxRate:Number(x.tax_rate||13),tax:Number(x.tax_amount||0),total:Number(x.total||0),currency:x.currency||'USD',notes:x.notes||'',paymentStatus:x.payment_status||'Pendiente',paymentDate:x.payment_date,paymentReceipt:x.payment_receipt,saleId:x.sale_id,updatedAt:x.updated_at,updatedByUserId:x.updated_by_user_id||null,updatedByUser:usersById[x.updated_by_user_id]?.name||'',seller:vs[x.seller_id]?.name||'',tour:ts[x.tour_id]?.name||''})),
    sales: sales.rows.map(x=>({id:x.id,number:x.number,op:x.operation_number,orderId:orders.rows.find(o=>o.sale_id===x.id)?.id||null,clientId:x.client_id,customerName:x.client_name,tourId:x.tour_id,tour:ts[x.tour_id]?.name||'',sellerId:x.seller_id,seller:vs[x.seller_id]?.name||'',serviceDate:x.service_date,pax:x.passengers,unitPrice:Number(x.unit_price||0),discount:Number(x.discount_percent||0),subtotal:Number(x.subtotal||0),discountAmount:Number(x.discount_amount||0),taxableAmount:Number(x.taxable_amount||0),taxRate:Number(x.tax_rate||13),tax:Number(x.tax_amount||0),total:Number(x.total||0),currency:x.currency||'USD'})),
    payments: payments.rows.map(x=>({id:x.id,number:x.number,supplierId:x.supplier_id,date:x.payment_date,receipt:x.receipt_number,total:Number(x.total||0),notes:x.notes||'',orderIds:links.rows.filter(l=>l.payment_id===x.id).map(l=>l.purchase_order_id)})),
    users: users.rows.map(x=>({id:x.id,name:x.name,email:x.email,role:x.role,active:x.active})),
    seq: Object.fromEntries(sequences.rows.map(x=>[x.code,Number(x.current_value)])),
    company: settings.rows[0] ? {commercial:settings.rows[0].commercial_name,legal:settings.rows[0].legal_name,id:settings.rows[0].legal_id,phone:settings.rows[0].phone,whatsapp:settings.rows[0].whatsapp,email:settings.rows[0].email,address:settings.rows[0].address,tax:Number(settings.rows[0].default_tax_rate||13)} : null
  };
}

async function replaceState(client, db) {
  await client.query('BEGIN');
  try {
    // IMPORTANTE:
    // Esta función ya NO elimina registros existentes.
    // Solo crea o actualiza los registros recibidos.
    // PostgreSQL queda como fuente permanente de información.

    for (const x of (db.clients || [])) {
      await client.query(`
        INSERT INTO clients(id,name,type,phone,email,currency,notes,active)
        VALUES($1,$2,$3,$4,$5,$6,$7,TRUE)
        ON CONFLICT(id) DO UPDATE SET
          name=EXCLUDED.name,
          type=EXCLUDED.type,
          phone=EXCLUDED.phone,
          email=EXCLUDED.email,
          currency=EXCLUDED.currency,
          notes=EXCLUDED.notes
      `,[x.id,x.name,x.type||null,x.phone||null,x.email||null,x.currency||'USD',x.notes||null]);
    }

    for (const x of (db.suppliers || [])) {
      await client.query(`
        INSERT INTO suppliers(id,name,contact,phone,email,notes,active)
        VALUES($1,$2,$3,$4,$5,$6,TRUE)
        ON CONFLICT(id) DO UPDATE SET
          name=EXCLUDED.name,
          contact=EXCLUDED.contact,
          phone=EXCLUDED.phone,
          email=EXCLUDED.email,
          notes=EXCLUDED.notes
      `,[x.id,x.name,x.contact||null,x.phone||null,x.email||null,x.notes||null]);
    }

    for (const x of (db.sellers || [])) {
      await client.query(`
        INSERT INTO sellers(id,name,email,phone,commission_rate,active)
        VALUES($1,$2,$3,$4,$5,TRUE)
        ON CONFLICT(id) DO UPDATE SET
          name=EXCLUDED.name,
          email=EXCLUDED.email,
          phone=EXCLUDED.phone,
          commission_rate=EXCLUDED.commission_rate
      `,[x.id,x.name,x.email||null,x.phone||null,Number(x.commissionRate||0)]);
    }

    for (const x of (db.tours || [])) {
      await client.query(`
        INSERT INTO tours(id,name,hotel_price,cost,currency,active)
        VALUES($1,$2,$3,$4,$5,TRUE)
        ON CONFLICT(id) DO UPDATE SET
          name=EXCLUDED.name,
          hotel_price=EXCLUDED.hotel_price,
          cost=EXCLUDED.cost,
          currency=EXCLUDED.currency
      `,[x.id,x.name,Number(x.hotel||0),Number(x.cost||0),x.currency||'USD']);
    }

    for (const x of (db.sales || [])) {
      await client.query(`
        INSERT INTO sales(
          id,number,operation_number,client_id,seller_id,tour_id,client_name,
          service_date,passengers,unit_price,subtotal,discount_percent,
          discount_amount,taxable_amount,tax_rate,tax_amount,total,currency
        )
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        ON CONFLICT(id) DO UPDATE SET
          client_id=EXCLUDED.client_id,
          seller_id=EXCLUDED.seller_id,
          tour_id=EXCLUDED.tour_id,
          client_name=EXCLUDED.client_name,
          service_date=EXCLUDED.service_date,
          passengers=EXCLUDED.passengers,
          unit_price=EXCLUDED.unit_price,
          subtotal=EXCLUDED.subtotal,
          discount_percent=EXCLUDED.discount_percent,
          discount_amount=EXCLUDED.discount_amount,
          taxable_amount=EXCLUDED.taxable_amount,
          tax_rate=EXCLUDED.tax_rate,
          tax_amount=EXCLUDED.tax_amount,
          total=EXCLUDED.total,
          currency=EXCLUDED.currency
      `,[
        x.id,x.number,x.op,x.clientId,x.sellerId,x.tourId,x.customerName,
        x.serviceDate,x.pax||1,Number(x.unitPrice||0),Number(x.subtotal||0),
        Number(x.discount||0),Number(x.discountAmount||0),
        Number(x.taxableAmount||((x.subtotal||0)-(x.discountAmount||0))),
        Number(x.taxRate ?? 13),Number(x.tax||0),Number(x.total||0),
        x.currency||'USD'
      ]);
    }

    for (const x of (db.orders || [])) {
      await client.query(`
        INSERT INTO purchase_orders(
          id,number,operation_number,client_id,supplier_id,seller_id,tour_id,
          client_name,issue_date,service_date,service_time,pickup_place,drop_off,
          passengers,unit_cost,subtotal,tax_rate,tax_amount,total,currency,
          notes,payment_status,payment_date,payment_receipt,sale_id
        )
        VALUES(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
          $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25
        )
        ON CONFLICT(id) DO UPDATE SET
          client_id=EXCLUDED.client_id,
          supplier_id=EXCLUDED.supplier_id,
          seller_id=EXCLUDED.seller_id,
          tour_id=EXCLUDED.tour_id,
          client_name=EXCLUDED.client_name,
          issue_date=EXCLUDED.issue_date,
          service_date=EXCLUDED.service_date,
          service_time=EXCLUDED.service_time,
          pickup_place=EXCLUDED.pickup_place,
          drop_off=EXCLUDED.drop_off,
          passengers=EXCLUDED.passengers,
          unit_cost=EXCLUDED.unit_cost,
          subtotal=EXCLUDED.subtotal,
          tax_rate=EXCLUDED.tax_rate,
          tax_amount=EXCLUDED.tax_amount,
          total=EXCLUDED.total,
          currency=EXCLUDED.currency,
          notes=EXCLUDED.notes,
          payment_status=EXCLUDED.payment_status,
          payment_date=EXCLUDED.payment_date,
          payment_receipt=EXCLUDED.payment_receipt,
          sale_id=EXCLUDED.sale_id
      `,[
        x.id,x.number,x.op,x.clientId,x.supplierId,x.sellerId,x.tourId,
        x.customerName,x.issueDate,x.serviceDate,x.time||null,x.place||null,x.dropOff||null,
        x.pax||1,Number(x.unitCost||0),Number(x.subtotal||0),
        Number(x.taxRate ?? 13),Number(x.tax||0),Number(x.total||0),
        x.currency||'USD',x.notes||null,x.paymentStatus||'Pendiente',
        x.paymentDate||null,x.paymentReceipt||null,x.saleId||null
      ]);
    }

    for (const x of (db.payments || [])) {
      await client.query(`
        INSERT INTO payments(id,number,supplier_id,payment_date,receipt_number,total,notes)
        VALUES($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT(id) DO UPDATE SET
          supplier_id=EXCLUDED.supplier_id,
          payment_date=EXCLUDED.payment_date,
          receipt_number=EXCLUDED.receipt_number,
          total=EXCLUDED.total,
          notes=EXCLUDED.notes
      `,[x.id,x.number,x.supplierId,x.date,x.receipt,Number(x.total||0),x.notes||null]);
    }

    // Solo se reconstruyen las relaciones de pagos.
    // Esto NO elimina OCs, pagos ni ningún dato operativo.
    await client.query('DELETE FROM payment_purchase_orders');

    for (const p of (db.payments || [])) {
      for (const oid of (p.orderIds || [])) {
        const o=(db.orders || []).find(z=>z.id===oid);
        if(o) {
          await client.query(`
            INSERT INTO payment_purchase_orders(payment_id,purchase_order_id,amount)
            VALUES($1,$2,$3)
          `,[p.id,oid,Number(o.total||0)]);
        }
      }
    }

    // Los consecutivos nunca deben retroceder.
    for (const [code,val] of Object.entries(db.seq || {})) {
      await client.query(`
        INSERT INTO sequences(code,current_value)
        VALUES($1,$2)
        ON CONFLICT(code)
        DO UPDATE SET current_value=GREATEST(sequences.current_value,EXCLUDED.current_value)
      `,[code,Number(val||0)]);
    }

    if (db.company) {
      await client.query(`
        UPDATE company_settings
        SET commercial_name=$1,
            legal_name=$2,
            legal_id=$3,
            phone=$4,
            whatsapp=$5,
            email=$6,
            address=$7,
            default_tax_rate=$8
        WHERE id=1
      `,[
        db.company.commercial,
        db.company.legal,
        db.company.id,
        db.company.phone,
        db.company.whatsapp,
        db.company.email,
        db.company.address,
        Number(db.company.tax||13)
      ]);
    }

    await client.query('COMMIT');

  } catch(e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

app.get('/api/state', async (req,res)=>{
  if(!req.session.user) return res.status(401).json({error:'No autenticado.'});
  const client=await pool.connect();
  try { res.json(await getState(client)); }
  catch(e){ console.error(e); res.status(500).json({error:'No se pudo leer la base de datos'}); }
  finally{client.release();}
});

app.put('/api/state', async (req,res)=>{
  if(!req.session.user) return res.status(401).json({error:'No autenticado.'});
  const client=await pool.connect();
  try { await replaceState(client,req.body||{}); res.json({ok:true}); }
  catch(e){ console.error(e); res.status(500).json({ok:false,error:e.message}); }
  finally{client.release();}
});

app.use((req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(port,()=>console.log(`Tour Manager escuchando en ${port}`));
