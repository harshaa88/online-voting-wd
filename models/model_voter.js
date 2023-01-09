'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class model_voter extends Model {
    resetPassword(password) {
      return this.update({ password });
    }

    static async createAVoter({ voter_id, password, election_id }) {
      return await this.create({
        voter_id,
        password,
        election_id,
        voted: false,
      });
    }

    static async getNumberOfVoterss(election_id) {
      return await this.count({
        where: {
          election_id,
        },
      });
    }

    static async gettVoters(election_id) {
      return await this.findAll({
        where: {
          election_id,
        },
        order: [["id", "ASC"]],
      });
    }

    static async getVoter(id) {
      return await this.findOne({
        where: {
          id,
        },
      });
    }

    static async deleteAVoter(id) {
      return await this.destroy({
        where: {
          id,
        },
      });
    }

    static associate(models) {
      // define association here
      model_voter.belongsTo(models.model_election, {
        foreignKey: "election_id",
      });
    }
  }
  model_voter.init({
    voter_id: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password:  {
      type: DataTypes.STRING,
      allowNull: false,
    },
    voted:  {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
    },
    role: {
      type: DataTypes.STRING,
      defaultValue: "voter",
    }
  }, {
    sequelize,
    modelName: 'model_voter',
  });
  return model_voter;
};