'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class ModelAdmin extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    resetPass(password) {
      return this.update({ password });
    }

    static create_a_new_admin({ first_name, last_name, email, password }) {
      return this.create({
        first_name,
        last_name,
        email,
        password,
      });
    }

    static associate(models) {
      // define association here
      ModelAdmin.hasMany(models.model_election, {
        foreignKey: "admin_id",
      });
    }
  }
  ModelAdmin.init({
    first_name: DataTypes.STRING,
    last_name: DataTypes.STRING,
    password: DataTypes.STRING,
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    role: {
      type: DataTypes.STRING,
      defaultValue: "admin",
    },
  }, {
    sequelize,
    modelName: 'ModelAdmin',
  });
  return ModelAdmin;
};