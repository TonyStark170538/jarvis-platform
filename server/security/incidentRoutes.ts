import { Router } from 'express';
import { z } from 'zod';
import { updateIncidentStatus } from './incidentLifecycle';

const router = Router();

const statusSchema = z.object({
  status: z.enum(['open', 'investigating', 'resolved']),
});

router.patch('/incidents/:id/status', async (req, res, next) => {
  try {
    const parsed = statusSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid incident status',
      });
    }

    const incident = await updateIncidentStatus(req.params.id, parsed.data.status);
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found',
      });
    }

    return res.json({ success: true, data: incident });
  } catch (error) {
    next(error);
  }
});

export default router;
