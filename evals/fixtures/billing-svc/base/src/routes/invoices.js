const express = require('express');
const prisma = require('../prisma');
const router = express.Router();

router.get('/', async (req, res) => {
  const take = Math.min(parseInt(req.query.take, 10) || 20, 100);
  const invoices = await prisma.invoice.findMany({ where: { orgId: req.user.orgId }, take });
  res.json(invoices);
});

router.get('/:id', async (req, res) => {
  const invoice = await prisma.invoice.findFirst({ where: { id: req.params.id, orgId: req.user.orgId } });
  if (!invoice) return res.status(404).json({ error: 'not found' });
  res.json(invoice);
});

module.exports = router;
