const _ = require('lodash');
const {StatusCodes} = require('http-status-codes');
const model = require("../models/bookingvw");
const {getPageNo, getPageSize} = require('../utils/helper');

exports.getAll = async (req, res, next) => {
	try {
		const pageNo = await getPageNo(req);
		const pageSize = await getPageSize(req);
		const offset = (pageNo - 1) * pageSize;
		const totalCount = await model.count();
		const data = await model.find(offset, pageSize);
		if (!_.isEmpty(data)) {
			const result = {
				pageNo: pageNo,
				pageSize: pageSize,
				totalCount: totalCount,
				records: data,
			};
			res.status(StatusCodes.OK).send(result);
		} else {
			res.status(StatusCodes.NOT_FOUND).send({message : "Not found."});
		}
	} catch (e) {
		console.log(`Error in getAll`, e);
		next(e);
	}
};

exports.getById = async (req, res, next) => {
	try {
		const ID = req.params.ID;

		const data = await model.findById(ID);
		if (!_.isEmpty(data)) {
			res.status(StatusCodes.OK).send(data[0]);
		} else {
			res.status(StatusCodes.NOT_FOUND).send({message : "Not found."});
		}
	} catch (e) {
		console.log(`Error in getById`, e);
		next(e);
	}
};

exports.create = async (req, res, next) => {
	try {
		const data = await model.insert(req.body);
		if (data) {
			res.status(StatusCodes.CREATED).send({message:'Record created'});
		} else {
			res.status(StatusCodes.NOT_FOUND).send({message : "Not found."});
		}
	} catch (e) {
		console.log(`Error in create`, e);
		next(e);
	}
};

exports.update = async (req, res, next) => {
	try {
		const ID = req.params.ID;

		//const id = req.params.id;
		const data = await model.update(ID, req.body);
		if (!_.isEmpty(data)) {
			res.status(StatusCodes.OK).send(data[0]);
		} else {
			res.status(StatusCodes.BAD_REQUEST).send({message : "Bad request."});
		}
	} catch (e) {
		console.log(`Error in update`, e);
		next(e);
	}
};

exports.remove = async (req, res, next) => {
	try {
		const ID = req.params.ID;

		//const id = req.params.id;
		const data = await model.remove(ID);
		if (data) {
			res.status(StatusCodes.OK).send({message : "Resource deleted"});
		} else {
			res.status(StatusCodes.BAD_REQUEST).send({message : "Bad request."});
		}
	} catch (e) {
		console.log(`Error in remove`, e);
		next(e);
	}
};

exports.search = async (req, res, next) => {
	try {
		const pageNo = await getPageNo(req);
		const pageSize = await getPageSize(req);
		const offset = (pageNo - 1) * pageSize;
		const searchKey = req.params.searchKey;
		const totalCount = await model.searchCount(searchKey.toLowerCase());
		const data = await model.search(offset, pageSize, searchKey.toLowerCase());
		if (!_.isEmpty(data)) {
			const result = {
				pageNo: pageNo,
				pageSize: pageSize,
				totalCount: totalCount,
				records: data,
			};
			res.status(StatusCodes.OK).send(result);
		} else {
			res.status(StatusCodes.NOT_FOUND).send({message : "Not found."});
		}
	} catch (e) {
		console.log(`Error in search`, e);
		next(e);
	}
};


