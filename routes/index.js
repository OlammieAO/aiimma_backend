const express = require('express');
const router = express.Router();
const checkAuth = require('../middleware/jwtVerify');
const tokenController = require('../controllers/token');
const uploadController = require('../controllers/upload');
const auth_onboardingController = require('../controllers/auth_onboarding');

const aiimma_trucksRouter = require('./aiimma_trucks');
const aiimma_truck_maintenance_journey_booking_detailsRouter = require('./aiimma_truck_maintenance_journey_booking_details');
const aiimma_transportersRouter = require('./aiimma_transporters');
const aiimma_transporter_truck_junctionRouter = require('./aiimma_transporter_truck_junction');
const aiimma_transporter_driver_junctionRouter = require('./aiimma_transporter_driver_junction');
const aiimma_tdosRouter = require('./aiimma_tdos');
const aiimma_staffsRouter = require('./aiimma_staffs');
const aiimma_rolesRouter = require('./aiimma_roles');
const aiimma_membersaccessRouter = require('./aiimma_membersaccess');
const aiimma_holdingbay_containers_uploadRouter = require('./aiimma_holdingbay_containers_upload');
const aiimma_driversRouter = require('./aiimma_drivers');
const aiimma_customers_deposit_balanceRouter = require('./aiimma_customers_deposit_balance');
const aiimma_bt_hb_customersRouter = require('./aiimma_bt_hb_customers');
const aiimma_booking_paymentsRouter = require('./aiimma_booking_payments');
const aiimma_agentsRouter = require('./aiimma_agents');
const aiimma_bookingvwRouter = require('./bookingvw');
const aiimma__users_access_auditingRouter = require('./aiimma__users_access_auditing');
const aiima_transporter_driver_bthb_bookingRouter = require('./aiima_transporter_driver_bthb_booking');


router.post('/onboarding', auth_onboardingController.onboarding);
router.post('/signin', auth_onboardingController.signin);
router.post('/token', tokenController.authLogin);

router.post('/upload', checkAuth, uploadController.uploadFile);

router.use('/aiimma_trucks', aiimma_trucksRouter);
router.use('/aiimma_truck_maintenance_journey_booking_details', aiimma_truck_maintenance_journey_booking_detailsRouter);
router.use('/aiimma_transporters', aiimma_transportersRouter);
router.use('/aiimma_transporter_truck_junction', aiimma_transporter_truck_junctionRouter);
router.use('/aiimma_transporter_driver_junction', aiimma_transporter_driver_junctionRouter);
router.use('/aiimma_tdos', aiimma_tdosRouter);
router.use('/aiimma_staffs', aiimma_staffsRouter);
router.use('/aiimma_roles', aiimma_rolesRouter);
router.use('/aiimma_membersaccess', aiimma_membersaccessRouter);
router.use('/aiimma_holdingbay_containers_upload', aiimma_holdingbay_containers_uploadRouter);
router.use('/aiimma_drivers', aiimma_driversRouter);
router.use('/aiimma_customers_deposit_balance', aiimma_customers_deposit_balanceRouter);
router.use('/aiimma_bt_hb_customers', aiimma_bt_hb_customersRouter);
router.use('/aiimma_booking_payments', aiimma_booking_paymentsRouter);
router.use('/aiimma_agents', aiimma_agentsRouter);
router.use('/booking', aiimma_bookingvwRouter);
router.use('/aiimma__users_access_auditing', aiimma__users_access_auditingRouter);
router.use('/aiima_transporter_driver_bthb_booking', aiima_transporter_driver_bthb_bookingRouter);

module.exports = router;
