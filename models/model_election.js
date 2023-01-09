'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class model_election extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static addAnElection({ election_name, admin_id, url }) {
      return this.create({
        election_name,
        url,
        admin_id,
      });
    }

    static launchAnElection(id) {
      return this.update(
        {
          launch: true,
        },
        {
          returning: true,
          where: {
            id,
          },
        }
      );
    }

    static getelections(admin_id) {
      return this.findAll({
        where: {
          admin_id,
        },
        order: [["id", "ASC"]],
      });
    }

    static getElection(id) {
      return this.findOne({
        where: {
          id,
        },
      });
    }

    static getElectionurl(url) {
      return this.findOne({
        where: {
          url,
        },
      });
    }

   

    static associate(models) {
      // define association here
      model_election.belongsTo(models.ModelAdmin, {
        foreignKey: "admin_id",
      });

      model_election.hasMany(models.model_questions, {
        foreignKey: "election_id",
      });

      model_election.hasMany(models.model_voter, {
        foreignKey: "election_id",
      });
    }
  }
  model_election.init({
    election_name:  {
      type: DataTypes.STRING,
      allowNull: false,
    },
    url: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    launch:  {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    end:  {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    }
  }, {
    sequelize,
    modelName: 'model_election',
  });
  return model_election;
};