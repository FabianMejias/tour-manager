const express = require('express');
const helmet = require('helmet');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL no está configurada. En Railway se inyecta automáticamente al conectar el servicio Postgres.');
  process.exit(1);
}

const pool = new Pool({ connectionString: databaseUrl, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const q = (text, params=[]) => pool.query(text, params);

app.get('/api/health', async (req,res) => {
  try { const r=await q('SELECT NOW() AS now'); res.json({ok:true, database:true, time:r.rows[0].now}); }
  catch(e){ res.status(500).json({ok:false,error:'Database connection failed'}); }
});

async function getState(client) {
  const [clients,suppliers,sellers,tours,orders,sales,payments,links,sequences,settings,users] = await Promise.all([
    client.query(`SELECT id,name,type,phone,email,currency,notes,active FROM clients ORDER BY name`),
    client.query(`SELECT id,name,contact,phone,email,notes,active FROM suppliers ORDER BY name`),
    client.query(`SELECT id,name,email,phone,commission_rate,active FROM sellers ORDER BY name`),
    client.query(`SELECT id,name,hotel_price,cost,currency,active FROM tours ORDER BY name`),
    client.query(`SELECT id,number,operation_number,client_id,supplier_id,seller_id,tour_id,client_name,issue_date,service_date,service_time,pickup_place,passengers,unit_cost,subtotal,tax_rate,tax_amount,total,currency,notes,payment_status,payment_date,payment_receipt,sale_id FROM purchase_orders ORDER BY number DESC`),
    client.query(`SELECT id,number,operation_number,client_id,seller_id,tour_id,client_name,service_date,passengers,unit_price,subtotal,discount_percent,discount_amount,taxable_amount,tax_rate,tax_amount,total,currency FROM sales ORDER BY number DESC`),
    client.query(`SELECT id,number,supplier_id,payment_date,receipt_number,total,notes FROM payments ORDER BY number DESC`),
    client.query(`SELECT payment_id,purchase_order_id,amount FROM payment_purchase_orders`),
    client.query(`SELECT code,current_value FROM sequences`),
    client.query(`SELECT commercial_name,legal_name,legal_id,phone,whatsapp,email,address,default_tax_rate FROM company_settings WHERE id=1`),
    client.query(`SELECT id,name,email,role,active FROM users ORDER BY name`)
  ]);
  const byId = (rows) => Object.fromEntries(rows.map(r=>[r.id,r]));
  const cs=byId(clients.rows), ss=byId(suppliers.rows), vs=byId(sellers.rows), ts=byId(tours.rows);
  return {
    clients: clients.rows.map(x=>({id:x.id,name:x.name,type:x.type||'',phone:x.phone||'',email:x.email||'',currency:x.currency||'USD',notes:x.notes||''})),
    suppliers: suppliers.rows.map(x=>({id:x.id,name:x.name,contact:x.contact||'',phone:x.phone||'',email:x.email||'',notes:x.notes||''})),
    sellers: sellers.rows.map(x=>({id:x.id,name:x.name,email:x.email||'',phone:x.phone||'',commissionRate:Number(x.commission_rate||0)})),
    tours: tours.rows.map(x=>({id:x.id,name:x.name,hotel:Number(x.hotel_price||0),cost:Number(x.cost||0),currency:x.currency||'USD'})),
    orders: orders.rows.map(x=>({id:x.id,number:x.number,op:x.operation_number,clientId:x.client_id,client:cs[x.client_id]?.name||'',supplierId:x.supplier_id,sellerId:x.seller_id,tourId:x.tour_id,customerName:x.client_name,issueDate:x.issue_date,serviceDate:x.service_date,time:x.service_time,place:x.pickup_place||'',pax:x.passengers,unitCost:Number(x.unit_cost||0),subtotal:Number(x.subtotal||0),taxRate:Number(x.tax_rate||13),tax:Number(x.tax_amount||0),total:Number(x.total||0),currency:x.currency||'USD',notes:x.notes||'',paymentStatus:x.payment_status||'Pendiente',paymentDate:x.payment_date,paymentReceipt:x.payment_receipt,saleId:x.sale_id,seller:vs[x.seller_id]?.name||'',tour:ts[x.tour_id]?.name||''})),
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
    // Clear dependent data first.
    await client.query('DELETE FROM payment_purchase_orders');
    await client.query('DELETE FROM purchase_orders');
    await client.query('DELETE FROM payments');
    await client.query('DELETE FROM sales');
    await client.query('DELETE FROM tours');
    await client.query('DELETE FROM sellers');
    await client.query('DELETE FROM suppliers');
    await client.query('DELETE FROM clients');

    for (const x of (db.clients||[])) await client.query(`INSERT INTO clients(id,name,type,phone,email,currency,notes,active) VALUES($1,$2,$3,$4,$5,$6,$7,TRUE)`,[x.id,x.name,x.type||null,x.phone||null,x.email||null,x.currency||'USD',x.notes||null]);
    for (const x of (db.suppliers||[])) await client.query(`INSERT INTO suppliers(id,name,contact,phone,email,notes,active) VALUES($1,$2,$3,$4,$5,$6,TRUE)`,[x.id,x.name,x.contact||null,x.phone||null,x.email||null,x.notes||null]);
    for (const x of (db.sellers||[])) await client.query(`INSERT INTO sellers(id,name,email,phone,commission_rate,active) VALUES($1,$2,$3,$4,$5,TRUE)`,[x.id,x.name,x.email||null,x.phone||null,Number(x.commissionRate||0)]);
    for (const x of (db.tours||[])) await client.query(`INSERT INTO tours(id,name,hotel_price,cost,currency,active) VALUES($1,$2,$3,$4,$5,TRUE)`,[x.id,x.name,Number(x.hotel||0),Number(x.cost||0),x.currency||'USD']);
    // Sales first, then OCs, because OCs may point to a sale.
    for (const x of (db.sales||[])) await client.query(`INSERT INTO sales(id,number,operation_number,client_id,seller_id,tour_id,client_name,service_date,passengers,unit_price,subtotal,discount_percent,discount_amount,taxable_amount,tax_rate,tax_amount,total,currency) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,[x.id,x.number,x.op,x.clientId,x.sellerId,x.tourId,x.customerName,x.serviceDate,x.pax||1,Number(x.unitPrice||0),Number(x.subtotal||0),Number(x.discount||0),Number(x.discountAmount||0),Number(x.taxableAmount||((x.subtotal||0)-(x.discountAmount||0))),Number(x.taxRate||13),Number(x.tax||0),Number(x.total||0),x.currency||'USD']);
    for (const x of (db.orders||[])) await client.query(`INSERT INTO purchase_orders(id,number,operation_number,client_id,supplier_id,seller_id,tour_id,client_name,issue_date,service_date,service_time,pickup_place,passengers,unit_cost,subtotal,tax_rate,tax_amount,total,currency,notes,payment_status,payment_date,payment_receipt,sale_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,[x.id,x.number,x.op,x.clientId,x.supplierId,x.sellerId,x.tourId,x.customerName,x.issueDate,x.serviceDate,x.time||null,x.place||null,x.pax||1,Number(x.unitCost||0),Number(x.subtotal||0),Number(x.taxRate||13),Number(x.tax||0),Number(x.total||0),x.currency||'USD',x.notes||null,x.paymentStatus||'Pendiente',x.paymentDate||null,x.paymentReceipt||null,x.saleId||null]);
    for (const x of (db.payments||[])) await client.query(`INSERT INTO payments(id,number,supplier_id,payment_date,receipt_number,total,notes) VALUES($1,$2,$3,$4,$5,$6,$7)`,[x.id,x.number,x.supplierId,x.date,x.receipt,Number(x.total||0),x.notes||null]);
    for (const p of (db.payments||[])) for (const oid of (p.orderIds||[])) { const o=(db.orders||[]).find(z=>z.id===oid); if(o) await client.query(`INSERT INTO payment_purchase_orders(payment_id,purchase_order_id,amount) VALUES($1,$2,$3)`,[p.id,oid,Number(o.total||0)]); }
    for (const [code,val] of Object.entries(db.seq||{})) await client.query(`INSERT INTO sequences(code,current_value) VALUES($1,$2) ON CONFLICT(code) DO UPDATE SET current_value=EXCLUDED.current_value`,[code,Number(val||0)]);
    if (db.company) await client.query(`UPDATE company_settings SET commercial_name=$1,legal_name=$2,legal_id=$3,phone=$4,whatsapp=$5,email=$6,address=$7,default_tax_rate=$8 WHERE id=1`,[db.company.commercial,db.company.legal,db.company.id,db.company.phone,db.company.whatsapp,db.company.email,db.company.address,Number(db.company.tax||13)]);
    await client.query('COMMIT');
  } catch(e) { await client.query('ROLLBACK'); throw e; }
}

app.get('/api/state', async (req,res)=>{
  const client=await pool.connect();
  try { res.json(await getState(client)); }
  catch(e){ console.error(e); res.status(500).json({error:'No se pudo leer la base de datos'}); }
  finally{client.release();}
});

app.put('/api/state', async (req,res)=>{
  const client=await pool.connect();
  try { await replaceState(client,req.body||{}); res.json({ok:true}); }
  catch(e){ console.error(e); res.status(500).json({ok:false,error:e.message}); }
  finally{client.release();}
});

app.use((req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(port,()=>console.log(`Tour Manager escuchando en ${port}`));
