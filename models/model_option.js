'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class model_option extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static getOptionss(question_id) {
      return this.findAll({
        where: {
          question_id,
        },
        order: [["id", "ASC"]],
      });
    }

    static getOption(id) {
      return this.findOne({
        where: {
          id,
        },
      });
    }

    static addAnOption({ choice, question_id }) {
      return this.create({
        choice,
        question_id,
      });
    }

    static updateAnOption({ choice, id }) {
      return this.update(
        {
          choice,
        },
        {
          where: {
            id,
          },
        }
      );
    }

    static deleteAnOption(id) {
      return this.destroy({
        where: {
          id,
        },
      });
    }

    static associate(models) {
      // define association here
      model_option.belongsTo(models.model_questions, {
        foreignKey: "question_id",
        onDelete: "CASCADE",
      });
    }
  }
  model_option.init({
    choice: {
      type: DataTypes.STRING,
      allowNull: false,
    }
  }, {
    sequelize,
    modelName: 'model_option',
  });
  return model_option;
};