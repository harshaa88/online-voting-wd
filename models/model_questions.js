'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class model_questions extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static async getNumberOfQuestionss(election_id) {
      return await this.count({
        where: {
          election_id,
        },
      });
    }

    static updateAQuestion({ question_name, question_description, id }) {
      return this.update(
        {
          question_name,
          question_description,
        },
        {
          returning: true,
          where: {
            id,
          },
        }
      );
    }

    static addAQuestion({ question_name, question_description, election_id }) {
      return this.create({
        question_name,
        question_description,
        election_id,
      });
    }

    static async getQuestion(id) {
      return await this.findOne({
        where: {
          id,
        },
      });
    }

    static deleteAQuestion(id) {
      return this.destroy({
        where: {
          id,
        },
      });
    }

    static async getQuestionss(election_id) {
      return await this.findAll({
        where: {
          election_id,
        },
        order: [["id", "ASC"]],
      });
    }

    static associate(models) {
      // define association here
      model_questions.belongsTo(models.model_election, {
        foreignKey: "election_id",
      });

      model_questions.hasMany(models.model_option, {
        foreignKey: "question_id",
      });
    }
  }
  model_questions.init({
    question_name:  {
      type: DataTypes.STRING,
      allowNull: false,
    },
    question_description: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'model_questions',
  });
  return model_questions;
};