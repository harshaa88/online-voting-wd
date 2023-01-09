'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    /**
     * Add altering commands here.
     *
     * Example:
     * await queryInterface.createTable('users', { id: Sequelize.INTEGER });
     */

    await queryInterface.addColumn("model_questions", "election_id", {
      type: Sequelize.DataTypes.INTEGER,
    });

    await queryInterface.addConstraint("model_questions", {
      fields: ["election_id"],
      type: "foreign key",
      references: {
        table: "model_elections",
        field: "id",
      },
    });
  },

  async down (queryInterface, Sequelize) {
    /**
     * Add reverting commands here.
     *
     * Example:
     * await queryInterface.dropTable('users');
     */
    await queryInterface.removeColumn("model_questions", "election_id");
  }
};

