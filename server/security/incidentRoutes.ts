import { Router } from 'express';
import { z } from 'zod';
import { addIncidentActivity, addIncidentNote, getIncidentActivity, getIncidentNotes } from './store';
import { updateIncidentAssignee, updateIncidentStatus } from './incidentLifecycle';

const router = Router();
const statusSchema = z.object({ status: z.enum(['open', 'investigating', 'resolved']) });
const assigneeSchema = z.object({ assignee: z.string().trim().min(1).max(120) });
const noteSchema = z.object({ body: z.string().trim().min(1).max(5000) });

function actor(req: Parameters<Parameters<typeof router.patch>[1]>[0]): string {
  const header = req.header('x-jarvis-actor');
  return header?.trim().slice(0, 120) || 'SOC Analyst';
}

router.patch('/incidents/:id/status', async (req, res, next) => {
  try {
    const parsed = statusSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: 'Invalid incident status' });
    const incident = await updateIncidentStatus(req.params.id, parsed.data.status, actor(req));
    if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });
    return res.json({ success: true, data: incident });
  } catch (error) { next(error); }
});

router.patch('/incidents/:id/assignee', async (req, res, next) => {
  try {
    const parsed = assigneeSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: 'Invalid assignee' });
    const incident = await updateIncidentAssignee(req.params.id, parsed.data.assignee, actor(req));
    if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });
    return res.json({ success: true, data: incident });
  } catch (error) { next(error); }
});

router.post('/incidents/:id/notes', async (req, res, next) => {
  try {
    const parsed = noteSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: 'Note body is required' });
    const note = await addIncidentNote(req.params.id, actor(req), parsed.data.body);
    await addIncidentActivity(req.params.id, 'note_added', actor(req), { noteId: note.id });
    return res.status(201).json({ success: true, data: note });
  } catch (error) { next(error); }
});

router.get('/incidents/:id/notes', async (req, res, next) => {
  try {
    return res.json({ success: true, data: await getIncidentNotes(req.params.id) });
  } catch (error) { next(error); }
});

router.get('/incidents/:id/activity', async (req, res, next) => {
  try {
    return res.json({ success: true, data: await getIncidentActivity(req.params.id) });
  } catch (error) { next(error); }
});

export default router;
