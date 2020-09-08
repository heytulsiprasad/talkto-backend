const isEmpty = (value) => {
	return (
		value === undefined ||
		value === null ||
		// because Object.keys(new Date()).length === 0;
		(typeof value === "object" &&
			Object.keys(value).length === 0 &&
			value.constructor === Object) ||
		(typeof value === "string" && value.trim().length === 0)
	);
};

module.exports = isEmpty;
